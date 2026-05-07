package com.hma.idpbrokerservice.presentation.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** /health and / — match the Node service info shape. */
@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, String> health() { return Map.of("status", "ok"); }

    @GetMapping("/logout")
    public Map<String, String> logout() {
        // No broker session to clear (matches Node behavior — logout is a no-op for the broker).
        return Map.of("logged_out", "true");
    }

    @GetMapping("/")
    public Map<String, Object> info() {
        return Map.of(
                "service", "iam-broker",
                "version", "4.0.0",
                "stack", "Spring Boot 3.5.10 / Java 21 / SOAP",
                "endpoints", Map.of(
                        "GET /sso/receive",                  "PID landing — auto-submits vendor token form",
                        "POST /ws (PublishToken)",           "Mint a vendor token",
                        "POST /ws (AuthenticateUser)",       "Vendor-side validate + single-use consume",
                        "POST /ws (OtpValidate)",            "WPC OTP validation",
                        "POST /ws (AdminRevoke)",            "Revoke token or user (admin-key required)",
                        "POST /ws (AdminBypass)",            "Create/cancel emergency bypass (MFA-gated)",
                        "GET /ws/publishtoken.wsdl",         "Contract"
                )
        );
    }
}
