package com.hma.idpbrokerservice.presentation.controller;

import com.hma.idpbrokerservice.sso.constants.IamCommentCodes;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PARAMIN;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PUBLISHOUT;
import com.hma.idpbrokerservice.sso.entity.SsoTokenHistory;
import com.hma.idpbrokerservice.sso.repository.SsoTokenHistoryRepository;
import com.hma.idpbrokerservice.sso.service.PublishTokenService;
import com.hma.idpbrokerservice.sso.service.client.DashboardEventClient;
import com.hma.idpbrokerservice.sso.service.support.NonceStore;
import com.hma.idpbrokerservice.sso.token.WpcOtpTokenGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Browser-facing entry to the broker. PID 302-redirects here with the
 * launch_token; we call PublishTokenService internally and auto-submit an
 * HTML form to the vendor URL — preserves the exact behavior of
 * poc/apps/iam-broker/src/routes/sso-launch.js.
 *
 * Cannot be SOAP: browsers don't speak SOAP and this is the redirect
 * landing for PID. All real broker logic lives in the SOAP services; this
 * controller is a thin shim.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class SsoReceiveController {

    private final PublishTokenService publishTokenService;
    private final SsoTokenHistoryRepository tokenHistoryRepo;
    private final WpcOtpTokenGenerator wpcGen;
    private final DashboardEventClient dashboard;
    private final NonceStore nonceStore;

    private static final long CSRF_TTL_MS = 5 * 60_000L;

    @GetMapping(value = "/sso/receive", produces = MediaType.TEXT_HTML_VALUE)
    public String receive(@RequestParam("launch_token") String launchTokenRaw,
                          @RequestParam(value = "flow_id", required = false) String flowId) {

        if (launchTokenRaw == null || launchTokenRaw.isBlank()) {
            return errorPage("Missing launch_token");
        }

        // Pull user_id + target_vendor + source_system out of the launch token.
        Map<String, String> claims = decodeClaims(launchTokenRaw);
        String uid = claims.getOrDefault("user_id", "");
        String target = claims.getOrDefault("target_vendor", "");
        String source = claims.getOrDefault("source_system", "");
        String fid = (flowId == null || flowId.isBlank())
                ? "sso-" + UUID.randomUUID().toString().substring(0, 8)
                : flowId;

        PARAMIN req = new PARAMIN();
        req.setLaunchToken(launchTokenRaw);
        req.setSourceSYSID(source);
        req.setTargetSYSID(target);
        req.setUserID(uid);
        req.setFlowID(fid);

        PUBLISHOUT out = publishTokenService.createToken(req);

        boolean ok = out.getERETURN() != null
                && IamCommentCodes.TYPE_SUCCESS.equals(out.getERETURN().getTYPE());
        if (!ok) {
            String msg = out.getERETURN() == null ? "UNKNOWN" : out.getERETURN().getMESSAGE();
            return errorPage(msg);
        }

        SsoTokenHistory hist = tokenHistoryRepo.findById(out.getJTI()).orElseThrow();

        // CSRF nonce — single-use guard for the broker→vendor hop. Same as
        // sso-launch.js:200-201; consumed via REST /token/consume by the
        // unchanged Node vendor-app.
        String csrfNonce = UUID.randomUUID().toString();
        nonceStore.register(csrfNonce, CSRF_TTL_MS);

        // Build the form fields the vendor expects, matching sso-launch.js:217-231.
        Map<String, String> fields = new LinkedHashMap<>();
        if ("wpc-otp".equals(out.getFormat())) {
            // WPC token wire was packed as "wpc:<encryptedUid>:<otp>"; split it back.
            String[] parts = out.getHtxtToken().split(":");
            String encryptedUid = parts.length >= 3 ? parts[1] : wpcGen.aesEcbHex(uid);
            String otp = parts.length >= 3 ? parts[2] : "";
            fields.put("cmd", "Login");
            fields.put("group", "GMA".equals(hist.getBrand()) ? "G_DEALER_USA" : "H_DEALER_USA");
            fields.put("reg", "USA");
            fields.put("userid", encryptedUid);
            fields.put("key", otp);
        } else {
            String fieldName = "saml".equals(out.getFormat()) ? "SAMLResponse" : "htxtToken";
            fields.put(fieldName, out.getHtxtToken());
        }
        fields.put("csrf_nonce", csrfNonce);
        fields.put("_flowId", fid);

        // Truncate token for display (don't show full token in dashboard)
        String tokenPreview = out.getHtxtToken();
        if (tokenPreview != null && tokenPreview.length() > 60) {
            tokenPreview = tokenPreview.substring(0, 60) + "... [" + tokenPreview.length() + " chars]";
        }

        Map<String, Object> tokenPayload = new LinkedHashMap<>();
        tokenPayload.put("format", out.getFormat());
        tokenPayload.put("jti", out.getJTI());
        tokenPayload.put("token_preview", tokenPreview);
        Map<String, Object> enrichedAttrs = new LinkedHashMap<>();
        if (out.getEnrichedAttributes() != null) {
            enrichedAttrs.putAll(out.getEnrichedAttributes());
        } else {
            enrichedAttrs.put("uid", hist.getUid() != null ? hist.getUid() : "");
            enrichedAttrs.put("role", hist.getRole() != null ? hist.getRole() : "");
            enrichedAttrs.put("brand", hist.getBrand() != null ? hist.getBrand() : "");
            enrichedAttrs.put("dealer_code", hist.getDealerCode() != null ? hist.getDealerCode() : "none");
        }

        tokenPayload.put("enriched_attributes", enrichedAttrs);
        tokenPayload.put("target_url", out.getURLD());
        tokenPayload.put("csrf_nonce", csrfNonce);

        dashboard.emit(Map.of(
                "flowId", fid, "flowType", "idp-initiated", "step", 12,
                "stepName", "BROKER_DELIVERS_TO_VENDOR", "service", "broker",
                "description", String.format("Broker minted %s token for \"%s\" (role: %s, brand: %s, dealer: %s). Token contains enriched attributes from PID + ENA. Auto-submitting to %s.",
                    out.getFormat(), hist.getUid(), hist.getRole(), hist.getBrand(),
                    hist.getDealerCode() != null ? hist.getDealerCode() : "none", out.getURLD()),
                "tokenPayload", tokenPayload,
                "redirect", Map.of("description", "Browser auto-submits to vendor", "url", out.getURLD()),
                "detail", Map.of("format", out.getFormat(), "jti", out.getJTI(), "field_count", fields.size())
        ));

        return autoSubmitHtml(out.getURLD(), fields);
    }

    private static String autoSubmitHtml(String action, Map<String, String> fields) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html><body><p>Redirecting...</p>");
        sb.append("<form method=\"post\" action=\"").append(escape(action)).append("\">");
        for (Map.Entry<String, String> e : fields.entrySet()) {
            sb.append("<input type=\"hidden\" name=\"").append(escape(e.getKey()))
              .append("\" value=\"").append(escape(e.getValue())).append("\">");
        }
        sb.append("</form><script>document.forms[0].submit();</script></body></html>");
        return sb.toString();
    }

    private static String errorPage(String msg) {
        return "<!DOCTYPE html><html><body><h2>SSO Error</h2><p>" + escape(msg) + "</p></body></html>";
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("\"", "&quot;")
                .replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Best-effort claim grab from the unsigned launch token. */
    private static Map<String, String> decodeClaims(String launchTokenRaw) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            String[] parts = launchTokenRaw.split("\\.");
            if (parts.length < 2) return out;
            String json = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            for (String key : new String[] {"user_id", "target_vendor", "source_system", "jti"}) {
                String marker = "\"" + key + "\":\"";
                int idx = json.indexOf(marker);
                if (idx < 0) continue;
                int s = idx + marker.length();
                int e = json.indexOf('"', s);
                if (e > s) out.put(key, json.substring(s, e));
            }
        } catch (Exception ignored) {}
        return out;
    }
}
