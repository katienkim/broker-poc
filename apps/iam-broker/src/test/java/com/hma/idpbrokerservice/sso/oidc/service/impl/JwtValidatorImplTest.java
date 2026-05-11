package com.hma.idpbrokerservice.sso.oidc.service.impl;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.domain.AuthenticatedUser;
import com.hma.idpbrokerservice.sso.oidc.exception.JwtValidationException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtValidatorImplTest {

    private static final String ISSUER = "https://test-idp/auth";
    private static final String CLIENT_ID = "test-client";
    private static final String KID = "test-key-1";

    private static RSAPrivateKey privateKey;
    private static RSAKey jwk;

    private SsoProperties properties;
    private JwtValidatorImpl validator;

    @BeforeAll
    static void generateKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        privateKey = (RSAPrivateKey) kp.getPrivate();
        jwk = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                .keyID(KID)
                .keyUse(KeyUse.SIGNATURE)
                .build();
    }

    @BeforeEach
    void setUp() {
        properties = new SsoProperties();
        SsoProperties.Oidc.Pid pid = properties.getOidc().getPid();
        pid.setIssuer(ISSUER);
        pid.setClientId(CLIENT_ID);

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        validator = new JwtValidatorImpl(properties, jwkSource);
    }

    @Test
    void acceptsValidToken() throws Exception {
        AuthenticatedUser user = validator.validate(signRs256(validClaims().build()));
        assertEquals("user-123", user.getSub());
        assertEquals("nonce-abc", user.getNonce());
        assertEquals(ISSUER, user.getIssuer());
        assertEquals("oidc", user.getSource());
    }

    @Test
    void rejectsBlankToken() {
        JwtValidationException e = assertThrows(JwtValidationException.class,
                () -> validator.validate(""));
        assertEquals("JWT_MISSING", e.getErrorCode());
    }

    @Test
    void rejectsMalformedToken() {
        JwtValidationException e = assertThrows(JwtValidationException.class,
                () -> validator.validate("not.a.real.token"));
        assertEquals("JWT_MALFORMED", e.getErrorCode());
    }

    @Test
    void rejectsHs256TokenWithRs256Required() throws Exception {
        // HMAC confusion attack — symmetric key signs a token claiming kid points to RSA cert.
        String hmacSecret = "test-secret-must-be-at-least-32-bytes-long-12345";
        JWSSigner hmac = new MACSigner(hmacSecret.getBytes(StandardCharsets.UTF_8));
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(KID).build(),
                validClaims().build());
        jwt.sign(hmac);
        JwtValidationException e = assertThrows(JwtValidationException.class,
                () -> validator.validate(jwt.serialize()));
        assertEquals("JWT_INVALID_ALG", e.getErrorCode());
    }

    @Test
    void rejectsBadSignature() throws Exception {
        // Generate a DIFFERENT RSA key, sign with that, but the public side isn't in our JWKSet.
        KeyPair other = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        JWSSigner signer = new RSASSASigner(other.getPrivate());
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(),
                validClaims().build());
        jwt.sign(signer);
        JwtValidationException e = assertThrows(JwtValidationException.class,
                () -> validator.validate(jwt.serialize()));
        assertEquals("JWT_INVALID_SIGNATURE", e.getErrorCode());
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        String token = signRs256(validClaims()
                .expirationTime(Date.from(Instant.now().minusSeconds(120)))
                .build());
        JwtValidationException e = assertThrows(JwtValidationException.class,
                () -> validator.validate(token));
        assertEquals("JWT_EXPIRED", e.getErrorCode());
    }

    @Test
    void rejectsFutureIssuedToken() throws Exception {
        String token = signRs256(validClaims()
                .issueTime(Date.from(Instant.now().plusSeconds(120)))
                .build());
        JwtValidationException e = assertThrows(JwtValidationException.class,
                () -> validator.validate(token));
        assertEquals("JWT_NOT_YET_VALID", e.getErrorCode());
    }

    @Test
    void rejectsWrongIssuer() throws Exception {
        String token = signRs256(validClaims().issuer("https://attacker/auth").build());
        JwtValidationException e = assertThrows(JwtValidationException.class,
                () -> validator.validate(token));
        assertEquals("JWT_INVALID_ISSUER", e.getErrorCode());
    }

    @Test
    void rejectsWrongAudience() throws Exception {
        String token = signRs256(validClaims().audience(List.of("some-other-client")).build());
        JwtValidationException e = assertThrows(JwtValidationException.class,
                () -> validator.validate(token));
        assertEquals("JWT_INVALID_AUDIENCE", e.getErrorCode());
    }

    @Test
    void rejectsMissingSubject() throws Exception {
        String token = signRs256(validClaims().subject(null).build());
        JwtValidationException e = assertThrows(JwtValidationException.class,
                () -> validator.validate(token));
        assertEquals("JWT_MISSING_SUB", e.getErrorCode());
    }

    @Test
    void extractsUserinfoIntoAttributes() throws Exception {
        Map<String, Object> userinfo = Map.of(
                "id", "User-xyz",
                "companyCode", "C1234",
                "userName", "Test User");
        AuthenticatedUser user = validator.validate(signRs256(
                validClaims().claim("userinfo", userinfo).build()));
        assertEquals("User-xyz", user.getAttributes().get("id"));
        assertEquals("C1234", user.getAttributes().get("companyCode"));
        assertEquals("Test User", user.getAttributes().get("userName"));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
                .subject("user-123")
                .issuer(ISSUER)
                .audience(CLIENT_ID)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("nonce", "nonce-abc");
    }

    private static String signRs256(JWTClaimsSet claims) throws Exception {
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(),
                claims);
        jwt.sign(signer);
        return jwt.serialize();
    }
}
