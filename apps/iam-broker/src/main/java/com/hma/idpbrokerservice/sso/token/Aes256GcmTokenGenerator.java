package com.hma.idpbrokerservice.sso.token;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.domain.IssuedToken;
import com.hma.idpbrokerservice.sso.domain.UserContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * AES-256-CBC — matches the Node POC vendor-app's decryption logic exactly.
 * Token wire format:  aes-v1:base64url(iv || ciphertext)
 * IV is 16 bytes, prepended to ciphertext.
 */
@Component
@RequiredArgsConstructor
public class Aes256GcmTokenGenerator {

    private static final String KID = "aes-v1";
    private static final int IV_LEN = 16;

    private final SsoProperties properties;

    public IssuedToken generate(UserContext user) {
        String jti = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(properties.getToken().getAes256().getTtlSeconds());

        String payload = "{\"jti\":\"" + jti + "\","
                + "\"uid\":\"" + esc(user.getUid()) + "\","
                + "\"role\":\"" + esc(user.getRole()) + "\","
                + "\"brand\":\"" + esc(user.getBrand()) + "\","
                + "\"dealer_code\":\"" + esc(user.getDealerCode()) + "\","
                + "\"first_name\":\"" + esc(user.getFirstName()) + "\","
                + "\"last_name\":\"" + esc(user.getLastName()) + "\","
                + "\"email\":\"" + esc(user.getEmail()) + "\","
                + "\"timestamp\":" + now.toEpochMilli() + "}";

        try {
            byte[] keyBytes = take32(properties.getToken().getAes256().getSharedKey());
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

            byte[] iv = new byte[IV_LEN];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] ct = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ct, 0, combined, iv.length, ct.length);

            String token = KID + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(combined);

            return IssuedToken.builder()
                    .token(token).format("aes256").jti(jti)
                    .issuedAt(now).expiresAt(exp)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("AES-CBC encrypt failed", e);
        }
    }

    private static byte[] take32(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        if (b.length >= 32) {
            byte[] out = new byte[32];
            System.arraycopy(b, 0, out, 0, 32);
            return out;
        }
        byte[] out = new byte[32];
        System.arraycopy(b, 0, out, 0, b.length);
        return out;
    }

    private static String esc(String s) { return s == null ? "" : s.replace("\"", "\\\""); }
}
