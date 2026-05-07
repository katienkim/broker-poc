package com.hma.idpbrokerservice.sso.token;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.constants.IamCommentCodes;
import com.hma.idpbrokerservice.sso.domain.IssuedToken;
import com.hma.idpbrokerservice.sso.domain.UserContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * IGTK = brand prefix (H_/G_) + SHA-256 of "src|tgt|uid|yyyyMMddHHmmssSSS".
 * Mirrors the client's TokenGenerator exactly (see client backend
 * sso/token/TokenGenerator.java). No JWT, no signature — the token is opaque
 * and validity is enforced by the DB row (expires_at + consumed flag).
 */
@Component
@RequiredArgsConstructor
public class IgtkTokenGenerator {

    private final SsoProperties properties;

    public IssuedToken generate(UserContext user, String sourceSysId, String targetSysId) {
        String prefix = "GMA".equalsIgnoreCase(user.getBrand())
                ? IamCommentCodes.GMA_FLAG : IamCommentCodes.HMA_FLAG;

        String ts = LocalDateTime.now().format(
                DateTimeFormatter.ofPattern(properties.getToken().getTimestampFormat()));
        String raw = sourceSysId + "|" + targetSysId + "|" + user.getUid() + "|" + ts;
        String hash = sha256Hex(raw);

        Instant now = Instant.now();
        Instant exp = now.plusSeconds(properties.getToken().getIgtk().getTtlSeconds());

        return IssuedToken.builder()
                .token(prefix + hash)
                .format("igtk")
                .jti(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiresAt(exp)
                .build();
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
