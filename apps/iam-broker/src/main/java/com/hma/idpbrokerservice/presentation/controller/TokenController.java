package com.hma.idpbrokerservice.presentation.controller;

import com.hma.idpbrokerservice.sso.entity.SsoTokenHistory;
import com.hma.idpbrokerservice.sso.repository.SsoRevocationRepository;
import com.hma.idpbrokerservice.sso.repository.SsoTokenHistoryRepository;
import com.hma.idpbrokerservice.sso.service.support.AuditService;
import com.hma.idpbrokerservice.sso.service.support.NonceStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * REST shim for unchanged Node mocks in /poc.
 * POST /token/validate — returns full enriched user profile (matches legacy SSOOUT)
 * POST /token/consume  — single-use CSRF nonce flip
 */
@RestController
@RequestMapping("/token")
@RequiredArgsConstructor
@Slf4j
public class TokenController {

    private final SsoTokenHistoryRepository tokenHistoryRepo;
    private final SsoRevocationRepository revocationRepo;
    private final NonceStore nonceStore;
    private final AuditService audit;

    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validate(@RequestBody Map<String, Object> body) {
        Object tokenObj = body.get("token");
        if (tokenObj == null || tokenObj.toString().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "token required"));
        }
        String token = tokenObj.toString();

        Optional<SsoTokenHistory> rowOpt = tokenHistoryRepo.findByToken(token);
        if (rowOpt.isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("valid", false, "error", "token invalid"));
        }
        SsoTokenHistory row = rowOpt.get();

        Instant now = Instant.now();
        if (row.getExpiresAt() != null && now.isAfter(row.getExpiresAt())) {
            return ResponseEntity.status(401).body(Map.of("valid", false, "error", "token expired"));
        }

        if (revocationRepo.findById("token:" + row.getJti())
                .filter(r -> now.isBefore(r.getExpiresAt())).isPresent()) {
            return ResponseEntity.status(401).body(Map.of("valid", false, "error", "TOKEN_REVOKED"));
        }
        var userRev = revocationRepo.findById("user:" + row.getUid());
        if (userRev.isPresent()
                && now.isBefore(userRev.get().getExpiresAt())
                && row.getIssuedAt() != null
                && row.getIssuedAt().isBefore(userRev.get().getRevokedAt())) {
            return ResponseEntity.status(401).body(Map.of("valid", false, "error", "USER_REVOKED"));
        }

        // Return attributes stored at token generation time (from the original ENA fetch)
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("valid", true);
        resp.put("uid", row.getUid());
        resp.put("role", row.getRole());
        resp.put("brand", row.getBrand());
        resp.put("dealer_code", row.getDealerCode());
        resp.put("user_type", "PID");
        if ("igtk".equals(row.getFormat())) resp.put("igtk", row.getToken());
        resp.put("kid", "igtk-v1");
        resp.put("expires_at", row.getExpiresAt() == null ? null : row.getExpiresAt().toString());
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/consume")
    public ResponseEntity<Map<String, Object>> consume(@RequestBody Map<String, Object> body) {
        Object idObj = body.get("id");
        if (idObj == null || idObj.toString().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "id required"));
        }
        String id = idObj.toString();

        if (!nonceStore.isRegistered(id)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "UNKNOWN_TOKEN",
                    "message", "Token ID not found in registry"));
        }
        boolean consumed = nonceStore.consume(id);
        if (!consumed) {
            audit.security("TOKEN_REPLAY", null, null, Map.of("id", id));
            return ResponseEntity.status(409).body(Map.of(
                    "error", "ALREADY_CONSUMED",
                    "message", "Token or nonce already used"));
        }
        audit.info("TOKEN_CONSUMED", null, null, Map.of("id", id));
        return ResponseEntity.ok(Map.of("consumed", true));
    }
}
