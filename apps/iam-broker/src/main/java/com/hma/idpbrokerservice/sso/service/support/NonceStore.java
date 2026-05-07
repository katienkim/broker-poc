package com.hma.idpbrokerservice.sso.service.support;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

/**
 * CSRF nonce single-use registry. Direct port of
 * poc/apps/iam-broker/src/lib/token-registry.js. Used by the REST shim at
 * /token/consume so unchanged Node mocks can drive the Spring broker.
 *
 * The DB-backed token-history (SsoTokenHistoryRepository.markConsumed) is the
 * canonical replay defense for SOAP callers; this in-memory map exists
 * alongside it for the REST compat path only.
 */
@Component
public class NonceStore {

    private final ConcurrentHashMap<String, Long> registry = new ConcurrentHashMap<>();

    public void register(String id, long ttlMs) {
        registry.put(id, System.currentTimeMillis() + ttlMs);
    }

    /** First call returns true; second call (or unknown id) returns false. */
    public boolean consume(String id) {
        Long exp = registry.remove(id);
        if (exp == null) return false;
        return System.currentTimeMillis() <= exp;
    }

    public boolean isRegistered(String id) {
        Long exp = registry.get(id);
        if (exp == null) return false;
        if (System.currentTimeMillis() > exp) {
            registry.remove(id);
            return false;
        }
        return true;
    }
}
