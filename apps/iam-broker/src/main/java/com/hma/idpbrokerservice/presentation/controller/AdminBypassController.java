package com.hma.idpbrokerservice.presentation.controller;

import com.hma.idpbrokerservice.sso.contract.adminbypassservice.BYPASSIN;
import com.hma.idpbrokerservice.sso.contract.adminbypassservice.BYPASSOUT;
import com.hma.idpbrokerservice.sso.service.AdminBypassService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/** REST shim — mirrors poc/apps/iam-broker/src/routes/bypass.js. */
@RestController
@RequestMapping("/admin/bypass")
@RequiredArgsConstructor
public class AdminBypassController {

    private final AdminBypassService service;

    @PostMapping
    public ResponseEntity<Map<String, Object>> create(
            @RequestHeader(value = "x-admin-key", required = false) String adminKey,
            @RequestHeader(value = "x-admin-mfa", required = false) String adminMfa,
            @RequestBody Map<String, Object> body) {

        BYPASSIN in = new BYPASSIN();
        in.setAction("create");
        in.setAdminKey(adminKey);
        in.setAdminMfa(adminMfa);
        in.setUserID(asString(body.get("user_id")));
        in.setTargetSystem(asString(body.get("target_system")));
        Object dur = body.get("duration_minutes");
        in.setDurationMinutes(dur == null ? null : Integer.parseInt(dur.toString()));
        in.setJustification(asString(body.get("justification")));

        BYPASSOUT out = service.execute(in);

        String msg = out.getERETURN() == null ? "ERROR" : out.getERETURN().getMESSAGE();
        if (out.getBypassID() == null) {
            int status = switch (msg) {
                case "UNAUTHORIZED" -> 401;
                case "MFA_REQUIRED" -> 403;
                default -> 400;
            };
            return ResponseEntity.status(status).body(Map.of("error", msg));
        }
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("bypass_id", out.getBypassID());
        resp.put("user_id", out.getUserID());
        resp.put("target_system", out.getTargetSystem());
        resp.put("expires_at", out.getExpiresAt());
        return ResponseEntity.ok(resp);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> cancel(
            @RequestHeader(value = "x-admin-key", required = false) String adminKey,
            @PathVariable String id) {

        BYPASSIN in = new BYPASSIN();
        in.setAction("cancel");
        in.setAdminKey(adminKey);
        in.setBypassID(id);
        BYPASSOUT out = service.execute(in);

        if (Boolean.TRUE.equals(out.getCancelled())) {
            return ResponseEntity.ok(Map.of("cancelled", true, "bypass_id", id));
        }
        String msg = out.getERETURN() == null ? "ERROR" : out.getERETURN().getMESSAGE();
        int status = "UNAUTHORIZED".equals(msg) ? 401 : 404;
        return ResponseEntity.status(status).body(Map.of("error", "BYPASS_NOT_FOUND"));
    }

    private static String asString(Object o) { return o == null ? null : o.toString(); }
}
