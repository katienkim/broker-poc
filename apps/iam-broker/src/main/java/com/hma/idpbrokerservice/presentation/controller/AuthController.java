package com.hma.idpbrokerservice.presentation.controller;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.constants.IamCommentCodes;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PARAMIN;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PUBLISHOUT;
import com.hma.idpbrokerservice.sso.domain.AuthenticatedUser;
import com.hma.idpbrokerservice.sso.entity.OAuthState;
import com.hma.idpbrokerservice.sso.oidc.dto.StateCodeValidationResult;
import com.hma.idpbrokerservice.sso.oidc.dto.TokenResponse;
import com.hma.idpbrokerservice.sso.oidc.exception.JwtValidationException;
import com.hma.idpbrokerservice.sso.oidc.exception.StateCodeNotFoundException;
import com.hma.idpbrokerservice.sso.oidc.exception.TokenExchangeException;
import com.hma.idpbrokerservice.sso.oidc.service.JwtValidator;
import com.hma.idpbrokerservice.sso.oidc.service.OidcStateCodeService;
import com.hma.idpbrokerservice.sso.oidc.service.TokenExchangeService;
import com.hma.idpbrokerservice.sso.service.PublishTokenService;
import com.hma.idpbrokerservice.sso.service.client.DashboardEventClient;
import com.hma.idpbrokerservice.sso.service.support.NonceStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * OIDC RP endpoints — ports the production
 * {@code iam-broker-poc/idp-ui-feature-Admin_System_Configuration/backend/.../AuthController}
 * {@code /login} and active {@code /callback} flow. Only registered when
 * {@code sso.oidc.pid.enabled=true}; until OIDC credentials are wired,
 * the bean is conditional-off and {@code /api/v1/auth/*} returns 404.
 *
 * Differences from production:
 *  - success path mints a downstream vendor token via {@link PublishTokenService}
 *    and auto-submits the HTML form (matches the SAML success path), instead of
 *    returning the id_token raw or routing through {@code SsoConfigService}
 *  - state row is the unified {@link OAuthState} also used by SAML RelayState
 *  - JWT validation delegates JWKS caching to Nimbus rather than a custom
 *    {@code IJwksProvider} + scheduler
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@ConditionalOnProperty(name = "sso.oidc.pid.enabled", havingValue = "true")
@Slf4j
public class AuthController {

    private static final long CSRF_TTL_MS = 5 * 60_000L;

    private final OidcStateCodeService stateCodeService;
    private final TokenExchangeService tokenExchangeService;
    private final JwtValidator jwtValidator;
    private final PublishTokenService publishTokenService;
    private final NonceStore nonceStore;
    private final SsoProperties properties;
    private final DashboardEventClient dashboard;

    /**
     * GET /api/v1/auth/login — redirects the browser to PID's authorize endpoint.
     * {@code target_vendor} is stored server-side keyed by the state code so
     * the callback can route the user to the right vendor after authentication.
     */
    @GetMapping("/login")
    public void login(
            @RequestParam("target_vendor") String targetVendor,
            @RequestParam(value = "application_parameter", required = false) String appParam,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        if (targetVendor == null || targetVendor.isBlank()) {
            response.sendError(400, "target_vendor required");
            return;
        }

        OAuthState state = stateCodeService.createStateCode(
                targetVendor, appParam, extractUserIp(request), request.getHeader("User-Agent"));

        String authorizeUrl = buildAuthorizeUrl(state.getStateCode(), state.getNonce());
        log.info("[OIDC] login init — targetVendor={} stateCode={} redirect={}",
                targetVendor, state.getStateCode(), authorizeUrl);

        dashboard.emit(Map.of(
                "flowId", state.getStateCode(),
                "flowType", "idp-initiated",
                "step", 1,
                "stepName", "OIDC_RP_LOGIN_INIT",
                "service", "broker",
                "description", "Broker creates state+nonce, redirects to PID /authorize. "
                        + "targetVendor=" + targetVendor,
                "detail", Map.of("stateCode", state.getStateCode(), "targetVendor", targetVendor)));

        response.sendRedirect(authorizeUrl);
    }

    /**
     * GET /api/v1/auth/callback — handles PID's redirect with {@code code} + {@code state}.
     * Ports the active /callback path from production AuthController.
     */
    @GetMapping("/callback")
    public void callback(
            @RequestParam(name = "code", required = false) String authCode,
            @RequestParam(name = "state", required = false) String stateCode,
            @RequestParam(name = "error", required = false) String error,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        if (error != null) {
            log.warn("[OIDC] error from PID: {}", error.replaceAll("[\r\n]", "_"));
            writeError(response, 401, "OIDC authentication failed: " + error);
            return;
        }
        if (authCode == null || stateCode == null) {
            writeError(response, 400, "Missing code or state");
            return;
        }

        StateCodeValidationResult v = stateCodeService.validateStateCode(stateCode);
        if (!v.isValid()) {
            writeError(response, 400, "Invalid state: " + v.getErrorMessage());
            return;
        }
        OAuthState state = v.getOauthState();
        String storedNonce = state.getNonce();
        if (storedNonce == null || storedNonce.isBlank()) {
            writeError(response, 500, "Nonce integrity error — please retry the login");
            return;
        }

        try {
            stateCodeService.markStateCodeAsUsed(stateCode);
        } catch (StateCodeNotFoundException e) {
            writeError(response, 404, "State code not found");
            return;
        }

        TokenResponse tokens;
        try {
            tokens = tokenExchangeService.exchangeCodeForTokens(authCode);
        } catch (TokenExchangeException e) {
            log.error("[OIDC] token exchange failed: {}", e.getMessage());
            writeError(response, 502, "Token exchange failed");
            return;
        }

        AuthenticatedUser user;
        try {
            user = jwtValidator.validate(tokens.getIdToken());
        } catch (JwtValidationException e) {
            log.error("[OIDC] id_token validation failed: {}", e.getMessage());
            writeError(response, 401, "id_token validation failed");
            return;
        }

        // Nonce binding — prevents token injection: the id_token must carry the
        // exact nonce we generated server-side at /login time.
        if (user.getNonce() == null || !user.getNonce().equals(storedNonce)) {
            log.error("[OIDC] nonce mismatch — possible token injection. sub={}", user.getSub());
            writeError(response, 401, "Nonce mismatch");
            return;
        }

        // Mint downstream vendor token, same as SAML success path.
        String flowId = "oidc-" + UUID.randomUUID().toString().substring(0, 8);
        PARAMIN req = new PARAMIN();
        req.setSourceSYSID("oidc-pid");
        req.setTargetSYSID(state.getTargetVendor());
        req.setUserID(user.getSub());
        req.setFlowID(flowId);

        PUBLISHOUT out = publishTokenService.createToken(req);
        boolean ok = out.getERETURN() != null
                && IamCommentCodes.TYPE_SUCCESS.equals(out.getERETURN().getTYPE());
        if (!ok) {
            String msg = out.getERETURN() == null ? "UNKNOWN" : out.getERETURN().getMESSAGE();
            writeError(response, 500, "Token minting failed: " + msg);
            return;
        }

        String csrfNonce = UUID.randomUUID().toString();
        nonceStore.register(csrfNonce, CSRF_TTL_MS);

        Map<String, String> fields = new LinkedHashMap<>();
        String fieldName = "saml".equals(out.getFormat()) ? "SAMLResponse" : "htxtToken";
        fields.put(fieldName, out.getHtxtToken());
        fields.put("csrf_nonce", csrfNonce);
        fields.put("_flowId", flowId);

        log.info("[OIDC] callback complete — sub={} targetVendor={} format={} jti={}",
                user.getSub(), state.getTargetVendor(), out.getFormat(), out.getJTI());

        dashboard.emit(Map.of(
                "flowId", state.getStateCode(),
                "flowType", "idp-initiated",
                "step", 7,
                "stepName", "OIDC_RP_VALIDATED_AND_MINTED",
                "service", "broker",
                "description", String.format(
                        "Broker exchanged code at /token, validated id_token (RS256 + JWKS + nonce), "
                                + "and minted %s downstream token for vendor \"%s\". Auto-submitting to %s.",
                        out.getFormat(), state.getTargetVendor(), out.getURLD()),
                "detail", Map.of(
                        "sub", user.getSub(),
                        "targetVendor", state.getTargetVendor(),
                        "format", out.getFormat(),
                        "jti", out.getJTI())));

        writeAutoSubmit(response, out.getURLD(), fields);
    }

    /** Diagnostic — confirms OIDC RP is wired and shows current config. */
    @GetMapping(value = "/status", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> status() {
        SsoProperties.Oidc.Pid cfg = properties.getOidc().getPid();
        return ResponseEntity.ok(Map.of(
                "enabled", cfg.isEnabled(),
                "issuer", cfg.getIssuer(),
                "authorizeEndpoint", cfg.getAuthorizeEndpoint(),
                "tokenEndpoint", cfg.getTokenEndpoint(),
                "jwksUri", cfg.getJwksUri(),
                "redirectUri", cfg.getRedirectUri(),
                "scopes", cfg.getScopes(),
                "loginUrl", "/api/v1/auth/login?target_vendor=<id>",
                "callbackUrl", "/api/v1/auth/callback"));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private String buildAuthorizeUrl(String stateCode, String nonce) {
        SsoProperties.Oidc.Pid cfg = properties.getOidc().getPid();
        StringBuilder sb = new StringBuilder(cfg.getAuthorizeEndpoint());
        sb.append(cfg.getAuthorizeEndpoint().contains("?") ? "&" : "?");
        sb.append("response_type=code");
        sb.append("&client_id=").append(enc(cfg.getClientId()));
        sb.append("&redirect_uri=").append(enc(cfg.getRedirectUri()));
        sb.append("&scope=").append(enc(cfg.getScopes()));
        sb.append("&state=").append(enc(stateCode));
        sb.append("&nonce=").append(enc(nonce));
        return sb.toString();
    }

    private static String enc(String s) {
        return s == null ? "" : URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String extractUserIp(HttpServletRequest req) {
        String fwd = req.getHeader("X-Forwarded-For");
        if (fwd != null && !fwd.isBlank()) return fwd.split(",")[0].trim();
        return req.getRemoteAddr();
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
