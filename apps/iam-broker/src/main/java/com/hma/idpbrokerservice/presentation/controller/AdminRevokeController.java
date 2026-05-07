package com.hma.idpbrokerservice.presentation.controller;

import com.hma.idpbrokerservice.sso.contract.adminrevokeservice.REVOKEIN;
import com.hma.idpbrokerservice.sso.contract.adminrevokeservice.REVOKEOUT;
import com.hma.idpbrokerservice.sso.service.AdminRevokeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** REST shim — mirrors poc/apps/iam-broker/src/routes/revoke.js. */
@RestController
@RequiredArgsConstructor
public class AdminRevokeController {

    private final AdminRevokeService service;

    @PostMapping("/admin/revoke")
    public ResponseEntity<Map<String, Object>> revoke(
            @RequestHeader(value = "x-admin-key", required = false) String adminKey,
            @RequestBody Map<String, Object> body) {

        REVOKEIN in = new REVOKEIN();
        in.setAdminKey(adminKey);
        in.setTokenID(asString(body.get("token_id")));
        in.setUserID(asString(body.get("user_id")));
        in.setReason(asString(body.get("reason")));

        REVOKEOUT out = service.revoke(in);

        if (!out.isRevoked()) {
            String msg = out.getERETURN() == null ? "ERROR" : out.getERETURN().getMESSAGE();
            int status = "UNAUTHORIZED".equals(msg) ? 401 : 400;
            return ResponseEntity.status(status).body(Map.of("error", msg));
        }
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("revoked", true);
        resp.put("type", out.getType());
        resp.put("id", out.getID());
        return ResponseEntity.ok(resp);
    }

    private static String asString(Object o) { return o == null ? null : o.toString(); }
}
