package com.hma.idpbrokerservice.sso.service.support;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MockPidTokenVerifierTest {

    private static final String SECRET = "test-secret-must-be-at-least-32-bytes-long-12345";

    private SsoProperties properties;
    private MockPidTokenVerifier verifier;

    @BeforeEach
    void setUp() {
        properties = new SsoProperties();
        SsoProperties.MockPid mockPid = new SsoProperties.MockPid();
        mockPid.setRequireSignature(true);
        mockPid.setSharedSecret(SECRET);
        properties.setMockPid(mockPid);
        verifier = new MockPidTokenVerifier(properties);
    }

    @Test
    void rejectsBlankToken() {
        MockPidTokenVerifier.VerificationException e =
                assertThrows(MockPidTokenVerifier.VerificationException.class,
                        () -> verifier.verifyAndExtractClaims(""));
        assertTrue(e.getMessage().toLowerCase().contains("blank"));
    }

    @Test
    void rejectsMalformedToken() {
        assertThrows(MockPidTokenVerifier.VerificationException.class,
                () -> verifier.verifyAndExtractClaims("not.a.jwt"));
    }

    @Test
    void rejectsAlgNoneToken() {
        // alg=none is the classic "skip signature" attack. Must be rejected.
        String noneToken = "eyJhbGciOiJub25lIn0"        // {"alg":"none"}
                + ".eyJ1c2VyX2lkIjoieCJ9"               // {"user_id":"x"}
                + ".";
        assertThrows(MockPidTokenVerifier.VerificationException.class,
                () -> verifier.verifyAndExtractClaims(noneToken));
    }

    @Test
    void rejectsRs256TokenWhenHs256Required() throws Exception {
        String rs256ShapedToken = signedHs256(claimsBuilder().build(), SECRET);
        // Hand-edit alg in header to "RS256" — should fail because we whitelist HS256.
        String[] parts = rs256ShapedToken.split("\\.");
        String tamperedHeader = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String tampered = tamperedHeader + "." + parts[1] + "." + parts[2];
        assertThrows(MockPidTokenVerifier.VerificationException.class,
                () -> verifier.verifyAndExtractClaims(tampered));
    }

    @Test
    void rejectsBadSignature() throws Exception {
        String token = signedHs256(claimsBuilder().build(), "wrong-secret-must-be-at-least-32-bytes-long");
        assertThrows(MockPidTokenVerifier.VerificationException.class,
                () -> verifier.verifyAndExtractClaims(token));
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        Instant pastExpiry = Instant.now().minusSeconds(60);
        String token = signedHs256(
                claimsBuilder().expirationTime(Date.from(pastExpiry)).build(),
                SECRET);
        MockPidTokenVerifier.VerificationException e = assertThrows(
                MockPidTokenVerifier.VerificationException.class,
                () -> verifier.verifyAndExtractClaims(token));
        assertTrue(e.getMessage().contains("expired"));
    }

    @Test
    void rejectsShortSecret() {
        properties.getMockPid().setSharedSecret("too-short");
        // build a token with the proper-length secret to get a valid-shape token,
        // then verify with the wrongly-configured (too-short) secret.
        assertThrows(MockPidTokenVerifier.VerificationException.class,
                () -> verifier.verifyAndExtractClaims(signedHs256(claimsBuilder().build(), SECRET)));
    }

    @Test
    void acceptsValidTokenAndExtractsClaims() throws Exception {
        String token = signedHs256(claimsBuilder()
                .claim("user_id", "DLR011001703")
                .claim("target_vendor", "vendor-saml")
                .claim("source_system", "dealers")
                .jwtID("abc-123")
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .build(), SECRET);

        Map<String, String> claims = verifier.verifyAndExtractClaims(token);
        assertEquals("DLR011001703", claims.get("user_id"));
        assertEquals("vendor-saml", claims.get("target_vendor"));
        assertEquals("dealers", claims.get("source_system"));
        assertEquals("abc-123", claims.get("jti"));
    }

    @Test
    void fallbackModeAcceptsUnsignedTokenAndLogsWarning() throws Exception {
        properties.getMockPid().setRequireSignature(false);

        // Unsigned-style token from the legacy mock-pid (just base64 payload).
        String payload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"user_id\":\"X\",\"target_vendor\":\"vendor-igtk\"}".getBytes(StandardCharsets.UTF_8));
        String legacyToken = "eyJ0eXAiOiJKV1QifQ." + payload + ".";

        Map<String, String> claims = verifier.verifyAndExtractClaims(legacyToken);
        // Legacy path returns best-effort claims without signature verification.
        assertEquals("X", claims.get("user_id"));
        assertEquals("vendor-igtk", claims.get("target_vendor"));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static JWTClaimsSet.Builder claimsBuilder() {
        return new JWTClaimsSet.Builder()
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)));
    }

    private static String signedHs256(JWTClaimsSet claims, String secret) throws Exception {
        JWSSigner signer = new MACSigner(secret.getBytes(StandardCharsets.UTF_8));
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(signer);
        return jwt.serialize();
    }
}
