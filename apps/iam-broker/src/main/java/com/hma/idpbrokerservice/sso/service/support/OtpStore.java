package com.hma.idpbrokerservice.sso.service.support;

import com.hma.idpbrokerservice.sso.domain.UserContext;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory OTP store. Direct port of the Map in
 * poc/apps/iam-broker/src/lib/tokens.js otpStore.
 * One instance shared by WpcOtpTokenGenerator (writer) and OtpService (reader).
 */
@Component
public class OtpStore {

    private record Entry(UserContext user, Instant expiresAt) {}

    private final ConcurrentHashMap<String, Entry> map = new ConcurrentHashMap<>();

    public void put(String otp, UserContext user, Instant expiresAt) {
        map.put(otp, new Entry(user, expiresAt));
    }

    /** Single-use take: returns the user once, then removes the entry. Expired entries are dropped. */
    public Optional<UserContext> consume(String otp) {
        Entry e = map.remove(otp);
        if (e == null) return Optional.empty();
        if (Instant.now().isAfter(e.expiresAt)) return Optional.empty();
        return Optional.of(e.user);
    }
}
