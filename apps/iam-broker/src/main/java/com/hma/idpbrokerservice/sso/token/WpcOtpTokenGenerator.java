package com.hma.idpbrokerservice.sso.token;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.domain.IssuedToken;
import com.hma.idpbrokerservice.sso.domain.UserContext;
import com.hma.idpbrokerservice.sso.service.support.OtpStore;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;

/**
 * WPC OTP: a 6-digit OTP + AES-256-ECB(uid) hex. Server keeps OTP→user
 * for {@link SsoProperties.WpcOtp#getTtlSeconds()} seconds. Validation goes
 * through OtpService.
 */
@Component
@RequiredArgsConstructor
public class WpcOtpTokenGenerator {

    private final SsoProperties properties;
    private final OtpStore otpStore;

    public IssuedToken generate(UserContext user) {
        String otp = String.valueOf(100000 + new SecureRandom().nextInt(900000));
        String encryptedUid = aesEcbHex(user.getUid());
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(properties.getToken().getWpcOtp().getTtlSeconds());

        otpStore.put(otp, user, exp);

        // The "token" string carried back to vendor isn't a single field — it's split
        // into {userid: encryptedUid, key: otp} by the broker before submit. We keep
        // both pieces here in a serialized form for token-history bookkeeping.
        String wireValue = "wpc:" + encryptedUid + ":" + otp;

        return IssuedToken.builder()
                .token(wireValue)
                .format("wpc-otp")
                .jti(otp)             // OTP doubles as the single-use id
                .issuedAt(now)
                .expiresAt(exp)
                .build();
    }

    public String aesEcbHex(String uid) {
        try {
            byte[] keyBytes = take32(properties.getToken().getAes256().getSharedKey());
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
            byte[] enc = c.doFinal(uid.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(enc.length * 2);
            for (byte b : enc) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("AES-ECB encrypt of uid failed", e);
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
}
