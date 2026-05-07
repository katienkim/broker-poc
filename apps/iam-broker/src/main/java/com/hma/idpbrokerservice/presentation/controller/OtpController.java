package com.hma.idpbrokerservice.presentation.controller;

import com.hma.idpbrokerservice.sso.contract.otpvalidateservice.OTPIN;
import com.hma.idpbrokerservice.sso.contract.otpvalidateservice.OTPOUT;
import com.hma.idpbrokerservice.sso.service.OtpValidateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST shim — mirrors poc/apps/iam-broker/src/routes/otp.js. Delegates to
 * the SOAP OtpValidateService underneath (same business logic, two transports).
 */
@RestController
@RequiredArgsConstructor
public class OtpController {

    private final OtpValidateService otpService;

    @PostMapping("/otp/validate")
    public ResponseEntity<Map<String, Object>> validate(@RequestBody Map<String, Object> body) {
        Object userid = body.get("userid");
        Object otp = body.get("otp");
        if (userid == null || otp == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "valid", false, "error", "Missing userid or otp"));
        }

        OTPIN in = new OTPIN();
        in.setUserID(userid.toString());
        in.setOtp(otp.toString());
        OTPOUT out = otpService.validate(in);

        if (out.isValid()) {
            Map<String, Object> user = new LinkedHashMap<>();
            var uc = out.getUserContext();
            if (uc != null) {
                user.put("uid", uc.getUid());
                user.put("role", uc.getRole());
                user.put("brand", uc.getBrand());
                user.put("dealer_code", uc.getDealerCode());
                user.put("first_name", uc.getFirstName());
                user.put("last_name", uc.getLastName());
                user.put("email", uc.getEmail());
                user.put("corporate_code", uc.getCorporateCode());
                user.put("corporate_name", uc.getCorporateName());
                user.put("department", uc.getDepartment());
            } else {
                user.put("uid", out.getUserID());
                user.put("role", out.getRole());
                user.put("brand", out.getBrand());
                user.put("dealer_code", out.getDealerCode());
            }
            return ResponseEntity.ok(Map.of("valid", true, "user", user, "uid", out.getUserID(),
                    "role", out.getRole(), "brand", out.getBrand(),
                    "dealer_code", out.getDealerCode() == null ? "" : out.getDealerCode()));
        }

        String msg = out.getERETURN() == null ? "OTP_INVALID" : out.getERETURN().getMESSAGE();
        int status = "OTP_LOCKED".equals(msg) ? 429 : 401;
        return ResponseEntity.status(status).body(Map.of("valid", false, "error", msg));
    }
}
