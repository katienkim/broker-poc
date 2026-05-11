package com.hma.idpbrokerservice.sso.oidc.service.impl;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.domain.AuthenticatedUser;
import com.hma.idpbrokerservice.sso.oidc.exception.JwtValidationException;
import com.hma.idpbrokerservice.sso.oidc.service.JwtValidator;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates HMG Partner ID id_tokens. Ports production
 * iam-broker-poc/idp-ui-feature-Admin_System_Configuration/backend/
 * .../JwtValidatorImpl.java verbatim for the security-critical logic;
 * delegates JWKS caching to Nimbus's {@code JWKSourceBuilder}.
 *
 * Defences (verbatim from production):
 *   - alg:none attack          → enforces RS256 only
 *   - HMAC key confusion       → key selector pinned to RS256
 *   - JKU/X5U header injection → never trusts header-embedded keys; only
 *                                fetches from the configured JWKS URI
 *   - Signature tampering      → Nimbus RSA-SHA256 verification
 *   - Expired token            → 30s clock skew allowance
 *   - Future-dated token       → iat must not be in the future
 *   - Wrong issuer / audience  → exact-match check against config
 *   - Unknown kid              → Nimbus retries the JWKS endpoint
 */
@Service
@ConditionalOnProperty(name = "sso.oidc.pid.enabled", havingValue = "true")
@Slf4j
public class JwtValidatorImpl implements JwtValidator {

    /** Configuration shim — produces the JWK source as a separate bean so tests
     *  can substitute a stub source without touching the validator class. */
    @Configuration
    @ConditionalOnProperty(name = "sso.oidc.pid.enabled", havingValue = "true")
    public static class Config {
        @Bean("pidJwkSource")
        public JWKSource<SecurityContext> pidJwkSource(SsoProperties properties) throws Exception {
            SsoProperties.Oidc.Pid cfg = properties.getOidc().getPid();
            if (cfg.getJwksUri() == null || cfg.getJwksUri().isBlank()) {
                throw new IllegalStateException("sso.oidc.pid.jwks-uri must be configured");
            }
            return JWKSourceBuilder.create(new URL(cfg.getJwksUri())).retrying(true).build();
        }
    }

    static final JWSAlgorithm REQUIRED_ALG = JWSAlgorithm.RS256;
    static final int CLOCK_SKEW_SECONDS = 30;

    private final SsoProperties properties;
    private final DefaultJWTProcessor<SecurityContext> jwtProcessor;

    public JwtValidatorImpl(SsoProperties properties,
                            @Qualifier("pidJwkSource") JWKSource<SecurityContext> jwkSource) {
        this.properties = properties;
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(REQUIRED_ALG, jwkSource);
        this.jwtProcessor = new DefaultJWTProcessor<>();
        this.jwtProcessor.setJWSKeySelector(keySelector);
        // Disable Nimbus's built-in claim verifier so our validateClaims() owns
        // every claim check end-to-end. Otherwise the framework swallows expired
        // tokens before our JWT_EXPIRED branch runs and reports a generic signature
        // failure instead.
        this.jwtProcessor.setJWTClaimsSetVerifier((claims, ctx) -> { /* no-op */ });
        SsoProperties.Oidc.Pid cfg = properties.getOidc().getPid();
        log.info("[JwtValidator] initialized — issuer={}", cfg.getIssuer());
    }

    @Override
    public AuthenticatedUser validate(String token) {
        SignedJWT signed = parse(token);
        enforceAlgorithm(signed.getHeader());
        JWTClaimsSet claims = verifyAndParse(signed);
        validateClaims(claims);
        return extractUser(claims);
    }

    private SignedJWT parse(String token) {
        if (token == null || token.isBlank()) {
            throw new JwtValidationException("Token is missing or blank", "JWT_MISSING");
        }
        try {
            JWT jwt = JWTParser.parse(token.trim());
            if (!(jwt instanceof SignedJWT s)) {
                throw new JwtValidationException("Token must be signed", "JWT_UNSIGNED");
            }
            return s;
        } catch (JwtValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new JwtValidationException("Malformed JWT: " + e.getMessage(), "JWT_MALFORMED");
        }
    }

    void enforceAlgorithm(JWSHeader header) {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!REQUIRED_ALG.equals(alg)) {
            throw new JwtValidationException(
                    "Invalid algorithm '" + (alg == null ? "none" : alg.getName())
                            + "'. Only RS256 is accepted",
                    "JWT_INVALID_ALG");
        }
    }

    private JWTClaimsSet verifyAndParse(SignedJWT signed) {
        try {
            return jwtProcessor.process(signed, null);
        } catch (com.nimbusds.jose.proc.BadJOSEException e) {
            throw new JwtValidationException(
                    "JWT signature verification failed: " + e.getMessage(),
                    "JWT_INVALID_SIGNATURE");
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new JwtValidationException(
                    "Signature verification error: " + e.getMessage(),
                    "JWT_SIGNATURE_ERROR");
        }
    }

    void validateClaims(JWTClaimsSet claims) {
        Instant now = Instant.now();
        SsoProperties.Oidc.Pid cfg = properties.getOidc().getPid();

        Date exp = claims.getExpirationTime();
        if (exp == null || exp.toInstant().plusSeconds(CLOCK_SKEW_SECONDS).isBefore(now)) {
            throw new JwtValidationException("JWT has expired", "JWT_EXPIRED");
        }

        Date iat = claims.getIssueTime();
        if (iat == null || iat.toInstant().minusSeconds(CLOCK_SKEW_SECONDS).isAfter(now)) {
            throw new JwtValidationException("JWT issued in the future", "JWT_NOT_YET_VALID");
        }

        if (!cfg.getIssuer().equals(claims.getIssuer())) {
            throw new JwtValidationException("Invalid issuer: " + claims.getIssuer(),
                    "JWT_INVALID_ISSUER");
        }

        List<String> audience = claims.getAudience();
        if (audience == null || !audience.contains(cfg.getClientId())) {
            throw new JwtValidationException(
                    "JWT audience does not include this client",
                    "JWT_INVALID_AUDIENCE");
        }

        if (claims.getSubject() == null || claims.getSubject().isBlank()) {
            throw new JwtValidationException("JWT missing subject claim", "JWT_MISSING_SUB");
        }
    }

    @SuppressWarnings("unchecked")
    private AuthenticatedUser extractUser(JWTClaimsSet claims) {
        Map<String, Object> attrs = new LinkedHashMap<>();
        Object userinfo = claims.getClaim("userinfo");
        if (userinfo instanceof Map<?, ?> m) {
            m.forEach((k, v) -> attrs.put(String.valueOf(k), v));
        }
        return AuthenticatedUser.builder()
                .sub(claims.getSubject())
                .nonce((String) claims.getClaim("nonce"))
                .issuer(claims.getIssuer())
                .source("oidc")
                .attributes(Map.copyOf(attrs))
                .build();
    }
}
