package com.hma.idpbrokerservice.sso.service.support;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Audit emitter. Direct port of poc/apps/iam-broker/src/lib/audit.js — one
 * JSON line per event on stdout, structured for log shippers.
 */
@Component
@Slf4j
public class AuditService {

    public void audit(String event, String level, String user, String target, String ip, Map<String, Object> detail) {
        Map<String, Object> entry = new HashMap<>();
        entry.put("ts", Instant.now().toString());
        entry.put("level", level == null ? "INFO" : level);
        entry.put("event", event);
        entry.put("user", user);
        entry.put("target", target);
        entry.put("ip", ip);
        entry.put("detail", detail == null ? Map.of() : detail);
        log.info("[Audit] {}", entry);
    }

    public void info(String event, String user, String target, Map<String, Object> detail) {
        audit(event, "INFO", user, target, null, detail);
    }

    public void security(String event, String user, String target, Map<String, Object> detail) {
        audit(event, "SECURITY", user, target, null, detail);
    }

    public void warn(String event, String user, String target, Map<String, Object> detail) {
        audit(event, "WARN", user, target, null, detail);
    }
}
