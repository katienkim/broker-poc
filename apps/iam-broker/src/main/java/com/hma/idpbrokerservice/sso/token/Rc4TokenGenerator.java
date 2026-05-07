package com.hma.idpbrokerservice.sso.token;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.domain.IssuedToken;
import com.hma.idpbrokerservice.sso.domain.UserContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * RC4 stream cipher + HMAC-SHA256 integrity tag. Direct port of the Node POC.
 * RC4 itself is deprecated and exists only to demonstrate the migration path —
 * a DEPRECATED_TOKEN audit event is logged on every issuance.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class Rc4TokenGenerator {

    private static final String KID = "rc4-v1";

    private final SsoProperties properties;

    public IssuedToken generate(UserContext user) {
        String jti = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(properties.getToken().getRc4().getTtlSeconds());

        log.warn("[Rc4Token] DEPRECATED_TOKEN issued for uid={}", user.getUid());

        String payload = "{\"jti\":\"" + jti + "\","
                + "\"uid\":\"" + esc(user.getUid()) + "\","
                + "\"role\":\"" + esc(user.getRole()) + "\","
                + "\"brand\":\"" + esc(user.getBrand()) + "\","
                + "\"dealer_code\":\"" + esc(user.getDealerCode()) + "\","
                + "\"first_name\":\"" + esc(user.getFirstName()) + "\","
                + "\"last_name\":\"" + esc(user.getLastName()) + "\","
                + "\"email\":\"" + esc(user.getEmail()) + "\","
                + "\"timestamp\":" + now.toEpochMilli() + "}";

        byte[] keyBytes = properties.getToken().getRc4().getSharedKey().getBytes(StandardCharsets.UTF_8);
        byte[] data = payload.getBytes(StandardCharsets.UTF_8);
        byte[] cipher = rc4(keyBytes, data);

        String hmac;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            byte[] tag = mac.doFinal(cipher);
            hmac = Base64.getUrlEncoder().withoutPadding().encodeToString(tag);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failed", e);
        }
        String token = KID + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(cipher) + "." + hmac;

        return IssuedToken.builder()
                .token(token).format("rc4").jti(jti)
                .issuedAt(now).expiresAt(exp)
                .build();
    }

    /** Plain RC4 — same algorithm as the Node version. */
    private static byte[] rc4(byte[] key, byte[] data) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + (key[i % key.length] & 0xff)) & 0xff;
            int t = s[i]; s[i] = s[j]; s[j] = t;
        }
        byte[] out = new byte[data.length];
        int x = 0; j = 0;
        for (int k = 0; k < data.length; k++) {
            x = (x + 1) & 0xff;
            j = (j + s[x]) & 0xff;
            int t = s[x]; s[x] = s[j]; s[j] = t;
            out[k] = (byte) ((data[k] & 0xff) ^ s[(s[x] + s[j]) & 0xff]);
        }
        return out;
    }

    private static String esc(String s) { return s == null ? "" : s.replace("\"", "\\\""); }
}
