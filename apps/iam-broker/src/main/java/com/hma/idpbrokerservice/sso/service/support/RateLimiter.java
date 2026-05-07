package com.hma.idpbrokerservice.sso.service.support;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-key sliding-window counter. Direct port of
 * poc/apps/iam-broker/src/lib/rate-limiter.js. Used today by the OTP path.
 */
@Component
public class RateLimiter {

    private static final class Bucket {
        int count;
        long windowStart;
        long windowMs;
    }

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public Result check(String key, int limit, long windowMs) {
        long now = System.currentTimeMillis();
        Bucket b = buckets.get(key);
        if (b == null || now - b.windowStart > b.windowMs) {
            Bucket fresh = new Bucket();
            fresh.count = 1;
            fresh.windowStart = now;
            fresh.windowMs = windowMs;
            buckets.put(key, fresh);
            return new Result(true, 0);
        }
        b.count++;
        if (b.count > limit) {
            long retryAfter = Math.max(1, (b.windowStart + windowMs - now + 999) / 1000);
            return new Result(false, retryAfter);
        }
        return new Result(true, 0);
    }

    public record Result(boolean allowed, long retryAfterSec) {}
}
