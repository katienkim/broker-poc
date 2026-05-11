package com.hma.idpbrokerservice.sso.service;

import com.hma.idpbrokerservice.sso.constants.IamCommentCodes;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PARAMIN;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PUBLISHOUT;
import com.hma.idpbrokerservice.sso.domain.AuthenticatedUser;
import com.hma.idpbrokerservice.sso.entity.OAuthState;
import com.hma.idpbrokerservice.sso.entity.SsoTokenHistory;
import com.hma.idpbrokerservice.sso.repository.OAuthStateRepository;
import com.hma.idpbrokerservice.sso.repository.SsoTokenHistoryRepository;
import com.hma.idpbrokerservice.sso.service.client.DashboardEventClient;
import com.hma.idpbrokerservice.sso.service.support.NonceStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Runs after Spring Security SAML2 has validated PID's assertion (signature,
 * Conditions, replay-guard). Looks up the {@code RelayState} state code to
 * recover the originally-requested target vendor, mints a downstream vendor
 * token via {@link PublishTokenService}, and returns the same auto-submit
 * HTML form pattern used by {@code SsoReceiveController}.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SamlSuccessHandler implements AuthenticationSuccessHandler {

    private static final long CSRF_TTL_MS = 5 * 60_000L;

    private final OAuthStateRepository stateRepo;
    private final PublishTokenService publishTokenService;
    private final SsoTokenHistoryRepository tokenHistoryRepo;
    private final NonceStore nonceStore;
    private final DashboardEventClient dashboard;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();

        AuthenticatedUser user = AuthenticatedUser.builder()
                .sub(principal.getName())
                .issuer(firstAttr(principal, "Issuer"))
                .source("saml")
                .attributes(principal.getAttributes() == null
                        ? Map.of() : Map.copyOf(principal.getAttributes()))
                .build();

        // Recover the original target_vendor via the RelayState round-trip.
        String relayState = request.getParameter("RelayState");
        if (relayState == null || relayState.isBlank()) {
            writeError(response, 400, "Missing RelayState — cannot determine target vendor");
            return;
        }

        Optional<OAuthState> stateOpt = stateRepo.findById(relayState);
        if (stateOpt.isEmpty()) {
            writeError(response, 400, "Unknown RelayState — state may have expired or already been consumed");
            return;
        }
        OAuthState state = stateOpt.get();
        if (state.isUsed()) {
            writeError(response, 400, "RelayState already used");
            return;
        }
        if (state.getExpiresAt() != null && Instant.now().isAfter(state.getExpiresAt())) {
            writeError(response, 400, "RelayState expired");
            return;
        }
        state.setUsed(true);
        stateRepo.save(state);

        String targetVendor = state.getTargetVendor();
        String sourceSystem = state.getSourceSystem() != null ? state.getSourceSystem() : "saml-pid";
        String flowId = "saml-" + UUID.randomUUID().toString().substring(0, 8);

        PARAMIN req = new PARAMIN();
        req.setSourceSYSID(sourceSystem);
        req.setTargetSYSID(targetVendor);
        req.setUserID(user.getSub());
        req.setFlowID(flowId);
        // LaunchToken intentionally null — the SAML assertion itself is the proof of auth.

        PUBLISHOUT out = publishTokenService.createToken(req);
        boolean ok = out.getERETURN() != null
                && IamCommentCodes.TYPE_SUCCESS.equals(out.getERETURN().getTYPE());
        if (!ok) {
            String msg = out.getERETURN() == null ? "UNKNOWN" : out.getERETURN().getMESSAGE();
            writeError(response, 500, "Token minting failed: " + msg);
            return;
        }

        SsoTokenHistory hist = tokenHistoryRepo.findById(out.getJTI()).orElseThrow();
        String csrfNonce = UUID.randomUUID().toString();
        nonceStore.register(csrfNonce, CSRF_TTL_MS);

        Map<String, String> fields = new LinkedHashMap<>();
        String fieldName = "saml".equals(out.getFormat()) ? "SAMLResponse" : "htxtToken";
        fields.put(fieldName, out.getHtxtToken());
        fields.put("csrf_nonce", csrfNonce);
        fields.put("_flowId", flowId);

        log.info("[SAML SP] sub={} -> targetVendor={} format={} jti={} (RelayState={})",
                user.getSub(), targetVendor, out.getFormat(), out.getJTI(), relayState);

        dashboard.emit(Map.of(
                "flowId", relayState,
                "flowType", "idp-initiated",
                "step", 8,
                "stepName", "SAML_SP_VALIDATED_AND_MINTED",
                "service", "broker",
                "description", String.format(
                        "Broker validated PID's SAML assertion (sig + Conditions + replay-guard), "
                                + "looked up state row, and minted %s downstream token for vendor \"%s\". "
                                + "Auto-submitting to %s.",
                        out.getFormat(), targetVendor, out.getURLD()),
                "detail", Map.of(
                        "sub", user.getSub(),
                        "targetVendor", targetVendor,
                        "format", out.getFormat(),
                        "jti", out.getJTI())));

        writeAutoSubmit(response, out.getURLD(), fields);
    }

    private static String firstAttr(Saml2AuthenticatedPrincipal principal, String key) {
        List<Object> values = principal.getAttribute(key);
        return values == null || values.isEmpty() ? null : String.valueOf(values.get(0));
    }

    private static void writeError(HttpServletResponse resp, int status, String msg) throws IOException {
        resp.setStatus(status);
        resp.setContentType("text/html");
        resp.getWriter().write(
                "<!DOCTYPE html><html><body><h2>SSO Error</h2><p>" + escape(msg) + "</p></body></html>");
    }

    private static void writeAutoSubmit(HttpServletResponse resp, String action, Map<String, String> fields)
            throws IOException {
        resp.setStatus(200);
        resp.setContentType("text/html");
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html><body><p>Redirecting...</p>");
        sb.append("<form method=\"post\" action=\"").append(escape(action)).append("\">");
        for (Map.Entry<String, String> e : fields.entrySet()) {
            sb.append("<input type=\"hidden\" name=\"").append(escape(e.getKey()))
                    .append("\" value=\"").append(escape(e.getValue())).append("\">");
        }
        sb.append("</form><script>document.forms[0].submit();</script></body></html>");
        resp.getWriter().write(sb.toString());
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
