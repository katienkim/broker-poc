package com.hma.idpbrokerservice.presentation.controller;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.entity.OAuthState;
import com.hma.idpbrokerservice.sso.entity.SsoSystem;
import com.hma.idpbrokerservice.sso.repository.OAuthStateRepository;
import com.hma.idpbrokerservice.sso.repository.SsoSystemRepository;
import com.hma.idpbrokerservice.sso.service.client.DashboardEventClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Kicks off the SP-initiated SAML flow. The user (or vendor SP) lands here
 * with {@code ?target_vendor=X}; the controller creates an {@link OAuthState}
 * row carrying the target, then redirects to Spring Security SAML2's
 * authentication initiator at {@code /saml2/authenticate/{registrationId}}
 * with the state code as {@code RelayState}.
 *
 * After the IdP round-trip, {@code SamlSuccessHandler} recovers the row by
 * RelayState and mints the downstream vendor token.
 */
@RestController
@RequestMapping("/api/v1/saml")
@RequiredArgsConstructor
@Slf4j
public class SamlLoginController {

    private final OAuthStateRepository stateRepo;
    private final SsoSystemRepository systemRepo;
    private final SsoProperties props;
    private final DashboardEventClient dashboard;

    @GetMapping("/login")
    public void login(
            @RequestParam("target_vendor") String targetVendor,
            @RequestParam(value = "source_system", required = false) String sourceSystem,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        if (targetVendor == null || targetVendor.isBlank()) {
            response.sendError(400, "target_vendor required");
            return;
        }

        Optional<SsoSystem> target = systemRepo.findById(targetVendor);
        if (target.isEmpty()) {
            response.sendError(404, "Unknown target vendor: " + targetVendor);
            return;
        }
        if (target.get().getIsSourceSysActive() != null && target.get().getIsSourceSysActive() == 0) {
            response.sendError(400, "Target vendor is inactive: " + targetVendor);
            return;
        }

        String stateCode = UUID.randomUUID().toString();
        Instant now = Instant.now();
        OAuthState state = OAuthState.builder()
                .stateCode(stateCode)
                .flow("saml")
                .targetVendor(targetVendor)
                .sourceSystem(sourceSystem)
                .userIp(extractUserIp(request))
                .userAgent(request.getHeader("User-Agent"))
                .used(false)
                .createdAt(now)
                .expiresAt(now.plusSeconds(60L * props.getOidc().getPid().getStateCodeExpiryMinutes()))
                .build();
        stateRepo.save(state);

        String redirect = "/saml2/authenticate/"
                + props.getSamlSp().getRegistrationId()
                + "?RelayState=" + URLEncoder.encode(stateCode, StandardCharsets.UTF_8);

        log.info("[SAML SP] login init — targetVendor={} stateCode={} redirect={}",
                targetVendor, stateCode, redirect);

        dashboard.emit(java.util.Map.of(
                "flowId", stateCode,
                "flowType", "idp-initiated",
                "step", 1,
                "stepName", "SAML_SP_LOGIN_INIT",
                "service", "broker",
                "description", "Broker creates state row, redirects to PID for SAML AuthnRequest. "
                        + "targetVendor=" + targetVendor,
                "detail", java.util.Map.of("stateCode", stateCode, "targetVendor", targetVendor)));

        response.sendRedirect(redirect);
    }

    /** Diagnostic — confirms the SAML SP is wired and lists the registration id. */
    @GetMapping(value = "/status", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> status() {
        SsoProperties.SamlSp cfg = props.getSamlSp();
        return ResponseEntity.ok(java.util.Map.of(
                "enabled", cfg.isEnabled(),
                "registrationId", cfg.getRegistrationId(),
                "entityId", cfg.getEntityId(),
                "acsUrl", cfg.getAcsUrl(),
                "metadataUrl", "/sso/saml/metadata",
                "loginUrl", "/api/v1/saml/login?target_vendor=<id>"));
    }

    private static String extractUserIp(HttpServletRequest req) {
        String fwd = req.getHeader("X-Forwarded-For");
        if (fwd != null && !fwd.isBlank()) return fwd.split(",")[0].trim();
        return req.getRemoteAddr();
    }
}
