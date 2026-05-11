package com.hma.idpbrokerservice.sso.service.support;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Verifies the launch token PID hands the browser (which the browser then
 * forwards to {@code GET /sso/receive?launch_token=...}).
 *
 * <p>Behavior gated by {@code sso.mock-pid.require-signature}:
 * <ul>
 *   <li>{@code true}  — token MUST be a valid HS256 JWT signed with
 *       {@code sso.mock-pid.shared-secret}. Bad signature / wrong algorithm
 *       / expired token → {@link VerificationException}.</li>
 *   <li>{@code false} — legacy behavior, base64-decode the JWT payload
 *       without verifying the signature. Logged loudly at WARN.</li>
 * </ul>
 *
 * <p>Mock-PID needs a small patch (see Phase 4 docs) before flipping the flag
 * on. Until then the broker keeps accepting unsigned tokens so the existing
 * stack doesn't break.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MockPidTokenVerifier {

    /** Claim keys we want pulled out of the JWT payload. */
    private static final Set<String> WANTED = Set.of(
            "user_id", "target_vendor", "source_system", "jti");

    private final SsoProperties properties;

    public Map<String, String> verifyAndExtractClaims(String launchToken) throws VerificationException {
        if (launchToken == null || launchToken.isBlank()) {
            throw new VerificationException("Launch token is blank");
        }

        SsoProperties.MockPid cfg = properties.getMockPid();
        if (cfg.isRequireSignature()) {
            return verifyHs256(launchToken, cfg.getSharedSecret());
        }
        log.warn("[MockPidTokenVerifier] sso.mock-pid.require-signature=false — "
                + "accepting unsigned launch token. Flip to true once mock-pid signs HS256.");
        return base64DecodeFallback(launchToken);
    }

    private static Map<String, String> verifyHs256(String launchToken, String sharedSecret)
            throws VerificationException {
        if (sharedSecret == null || sharedSecret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new VerificationException(
                    "HS256 secret missing or shorter than 32 bytes — refusing to verify");
        }
        try {
            SignedJWT jwt = SignedJWT.parse(launchToken);
            JWSHeader header = jwt.getHeader();
            if (!JWSAlgorithm.HS256.equals(header.getAlgorithm())) {
                throw new VerificationException("Unexpected JWS alg: " + header.getAlgorithm()
                        + " (only HS256 accepted)");
            }
            JWSVerifier verifier = new MACVerifier(sharedSecret.getBytes(StandardCharsets.UTF_8));
            if (!jwt.verify(verifier)) {
                throw new VerificationException("HS256 signature verification failed");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Instant exp = claims.getExpirationTime() == null
                    ? null : claims.getExpirationTime().toInstant();
            if (exp != null && Instant.now().isAfter(exp)) {
                throw new VerificationException("Launch token expired at " + exp);
            }
            Map<String, String> out = new LinkedHashMap<>();
            for (String key : WANTED) {
                Object v = claims.getClaim(key);
                if (v != null) out.put(key, v.toString());
            }
            return out;
        } catch (ParseException e) {
            throw new VerificationException("Launch token is not a valid JWT: " + e.getMessage());
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new VerificationException("JWS verification error: " + e.getMessage());
        }
    }

    /** Legacy behavior — kept only while {@code require-signature=false}. */
    private static Map<String, String> base64DecodeFallback(String launchToken) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            String[] parts = launchToken.split("\\.");
            if (parts.length < 2) return out;
            String json = new String(
                    Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            for (String key : WANTED) {
                String marker = "\"" + key + "\":\"";
                int idx = json.indexOf(marker);
                if (idx < 0) continue;
                int s = idx + marker.length();
                int e = json.indexOf('"', s);
                if (e > s) out.put(key, json.substring(s, e));
            }
        } catch (Exception ignored) {
            // Best-effort — legacy callers may send malformed tokens.
        }
        return out;
    }

    public static class VerificationException extends Exception {
        public VerificationException(String msg) { super(msg); }
    }
}
