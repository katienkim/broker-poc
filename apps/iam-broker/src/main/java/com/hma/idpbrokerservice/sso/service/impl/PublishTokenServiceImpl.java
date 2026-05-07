package com.hma.idpbrokerservice.sso.service.impl;

import com.hma.idpbrokerservice.sso.constants.IamCommentCodes;
import com.hma.idpbrokerservice.sso.contract.Ereturn;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PARAMIN;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PUBLISHOUT;
import com.hma.idpbrokerservice.sso.domain.IssuedToken;
import com.hma.idpbrokerservice.sso.domain.UserContext;
import com.hma.idpbrokerservice.sso.entity.SsoSystem;
import com.hma.idpbrokerservice.sso.entity.SsoTokenHistory;
import com.hma.idpbrokerservice.sso.enums.TokenFormat;
import com.hma.idpbrokerservice.sso.repository.SsoSystemRepository;
import com.hma.idpbrokerservice.sso.repository.SsoTokenHistoryRepository;
import com.hma.idpbrokerservice.sso.service.PublishTokenService;
import com.hma.idpbrokerservice.sso.service.client.DealersAttributeClient;
import com.hma.idpbrokerservice.sso.service.client.DashboardEventClient;
import com.hma.idpbrokerservice.sso.service.client.PidLaunchTokenClient;
import com.hma.idpbrokerservice.sso.service.support.AuditService;
import com.hma.idpbrokerservice.sso.token.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

/**
 * Mirrors poc/apps/iam-broker/src/routes/sso-launch.js step-for-step:
 *   step 9  — re-validate launch token with PID
 *   step 10 — fetch attrs from Dealers
 *   step 11 — system-level validation (target known + active) + token aggregation
 *   step 12 — mint vendor token, persist history row
 *
 * Per Yoonmi/Ahn Dae Hyun: NO user-level permission check — that ownership
 * sits with Dealers. Broker only confirms the target system exists/is active
 * and aggregates the identity claims.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PublishTokenServiceImpl implements PublishTokenService {

    private final PidLaunchTokenClient pidClient;
    private final DealersAttributeClient dealersClient;
    private final SsoSystemRepository systemRepo;
    private final SsoTokenHistoryRepository tokenHistoryRepo;
    private final AuditService audit;

    private final IgtkTokenGenerator igtkGen;
    private final SamlTokenGenerator samlGen;
    private final Aes256GcmTokenGenerator aesGen;
    private final Rc4TokenGenerator rc4Gen;
    private final WpcOtpTokenGenerator wpcGen;
    private final DashboardEventClient dashboard;

    @Override
    @Transactional
    public PUBLISHOUT createToken(PARAMIN req) {
        log.info("[PublishToken] createToken: source={}, target={}, uid={}, flow={}",
                req.getSourceSYSID(), req.getTargetSYSID(), req.getUserID(), req.getFlowID());
        String fid = req.getFlowID() != null ? req.getFlowID() : "sso-unknown";

        // step 9 — re-validate launch token with PID (defense in depth)
        if (req.getLaunchToken() != null && !req.getLaunchToken().isBlank()) {
            String jti = decodeJti(req.getLaunchToken());
            dashboard.emit(Map.of(
                "flowId", fid, "flowType", "idp-initiated", "step", 9,
                "stepName", "BROKER_VALIDATES_LAUNCH_TOKEN", "service", "broker",
                "description", "Broker received launch token from PID. Decoding and re-validating with PID (defense-in-depth). JTI: " + (jti.length() > 12 ? jti.substring(0, 12) + "..." : jti),
                "detail", Map.of("jti", jti, "user_id", req.getUserID(), "target_vendor", req.getTargetSYSID())
            ));
            Map<String, Object> r = pidClient.validate(jti);
            if (r == null || !Boolean.TRUE.equals(r.get("valid"))) {
                dashboard.emit(Map.of(
                    "flowId", fid, "flowType", "idp-initiated", "step", 9,
                    "stepName", "LAUNCH_TOKEN_REJECTED", "service", "broker",
                    "description", "PID rejected the launch token on broker-side re-validation. Possible replay or forged token.",
                    "httpResponse", Map.of("status", "error", "body", r != null ? r : Map.of("error", "null response"))
                ));
                return error(req, IamCommentCodes.MSG_LAUNCH_TOKEN_INVALID);
            }
            dashboard.emit(Map.of(
                "flowId", fid, "flowType", "idp-initiated", "step", 9,
                "stepName", "LAUNCH_TOKEN_VALIDATED", "service", "broker",
                "description", String.format("Launch token validated. User: \"%s\", Target: \"%s\", Source: \"%s\". Token consumed (one-time use).", req.getUserID(), req.getTargetSYSID(), req.getSourceSYSID()),
                "tokenPayload", Map.of("jti", jti, "user_id", req.getUserID(), "target_vendor", req.getTargetSYSID(), "source_system", req.getSourceSYSID()),
                "httpResponse", Map.of("status", 200, "body", Map.of("valid", true))
            ));
        }

        // step 11 (system-level) — target system must exist and be active
        Optional<SsoSystem> sysOpt = systemRepo.findById(req.getTargetSYSID());
        if (sysOpt.isEmpty()) return error(req, IamCommentCodes.MSG_TARGET_NOT_FOUND);
        SsoSystem sys = sysOpt.get();
        if (sys.getIsSourceSysActive() == null || sys.getIsSourceSysActive() != 1) {
            return error(req, IamCommentCodes.MSG_TARGET_INACTIVE);
        }

        // step 10 — Dealers enrichment (token aggregation)
        dashboard.emit(Map.of(
            "flowId", fid, "flowType", "idp-initiated", "step", 10,
            "stepName", "BROKER_REQUESTS_DEALER_ATTRS", "service", "broker",
            "description", String.format("Broker calling Dealers Attribute API (ENA) to fetch vendor-required attributes for user \"%s\". PID provided base identity (4 claims: pid, hmgpid, dealer_code, roles); ENA provides role, brand, dealer_code, department, zone, district.", req.getUserID()),
            "httpRequest", Map.of("method", "GET", "url", "ENA /users/" + req.getUserID())
        ));
        Map<String, Object> attrs = dealersClient.fetchAttributes(req.getUserID());
        UserContext user = UserContext.builder()
                .uid(req.getUserID())
                .role(asString(attrs.get("role"), "UNKNOWN"))
                .brand(asString(attrs.get("brand"), "H"))
                .dealerCode(asString(attrs.get("dealer_code"), null))
                .userType("PID")
                .firstName(asString(attrs.get("first_name"), ""))
                .lastName(asString(attrs.get("last_name"), ""))
                .email(asString(attrs.get("email"), ""))
                .corporateCode(asString(attrs.get("corporate_code"), "00000"))
                .corporateName(asString(attrs.get("corporate_name"), ""))
                .jobCode(asString(attrs.get("job_code"), ""))
                .jobTitle(asString(attrs.get("job_title"), ""))
                .department(asString(attrs.get("department"), ""))
                .position(asString(attrs.get("position"), ""))
                .regionCode(asString(attrs.get("region_code"), ""))
                .salesDistrict(asString(attrs.get("sales_district"), ""))
                .serviceDistrict(asString(attrs.get("service_district"), ""))
                .partsDistrict(asString(attrs.get("parts_district"), ""))
                .dealerStateCode(asString(attrs.get("dealer_state_code"), ""))
                .dealerTypeCode(asString(attrs.get("dealer_type_code"), ""))
                .zone(asString(attrs.get("zone"), ""))
                .district(asString(attrs.get("district"), ""))
                .accessLevel(asString(attrs.get("access_level"), ""))
                .permissionGroups(asString(attrs.get("permission_groups"), ""))
                .build();

        // Count actual attributes that will be embedded in the vendor token
        // (varies by format — not all ENA attrs make it into every token type)
        int tokenAttrCount = switch (TokenFormat.from(sys.getSourceSysType())) {
            case IGTK    -> 17; // uid, firstName, lastName, corporateCode, corporateName, jobCode, jobTitle, regionCode, salesDistrict, serviceDistrict, partsDistrict, dealerCode, dealerStateCode, dealerTypeCode, email, accessLevel, permissionGroups
            case SAML    -> 10; // uid (NameID), jti, role, brand, dealerCode, firstName, lastName, email, company, zone
            case AES256  -> 8;  // uid, role, brand, dealerCode, firstName, lastName, email, timestamp
            case RC4     -> 8;  // uid, role, brand, dealerCode, firstName, lastName, email, timestamp
            case WPC_OTP -> 4;  // uid (encrypted), otp, group, region
            case UNKNOWN -> 0;
        };

        dashboard.emit(Map.of(
            "flowId", fid, "flowType", "idp-initiated", "step", 11,
            "stepName", "DEALERS_RETURNS_ATTRS_AND_SYSTEM_CHECK", "service", "broker",
            "description", String.format("ENA returned %d attributes for \"%s\" (role: %s, brand: %s, dealer: %s). Target system \"%s\" (%s) is %s. Token will contain %d enriched attributes.",
                attrs.size(), user.getUid(), user.getRole(), user.getBrand(),
                user.getDealerCode() != null ? user.getDealerCode() : "none",
                sys.getSourceSysName(), sys.getSourceSysType(),
                sys.getIsSourceSysActive() == 1 ? "ACTIVE" : "INACTIVE",
                tokenAttrCount),
            "httpResponse", Map.of("status", attrs.isEmpty() ? 404 : 200, "body", attrs),
            "sessionData", Map.of("uid", user.getUid(), "role", user.getRole(), "brand", user.getBrand(), "dealer_code", user.getDealerCode() != null ? user.getDealerCode() : "none", "user_type", "PID"),
            "detail", Map.of("ena_attrs_fetched", attrs.size(), "token_attrs_embedded", tokenAttrCount, "token_format", sys.getSourceSysType(), "target_system", sys.getSourceSysName(), "target_active", sys.getIsSourceSysActive() == 1)
        ));

        // step 12 — mint vendor token
        TokenFormat format = TokenFormat.from(sys.getSourceSysType());
        IssuedToken issued = switch (format) {
            case IGTK    -> igtkGen.generate(user, req.getSourceSYSID(), req.getTargetSYSID());
            case SAML    -> samlGen.generate(user, sys.getDirectReurlD());
            case AES256  -> aesGen.generate(user);
            case RC4     -> rc4Gen.generate(user);
            case WPC_OTP -> wpcGen.generate(user);
            case UNKNOWN -> null;
        };
        if (issued == null) return error(req, IamCommentCodes.MSG_BAD_REQUEST);

        // persist (replaces in-memory tokenRegistry)
        SsoTokenHistory hist = new SsoTokenHistory();
        hist.setJti(issued.getJti());
        hist.setFormat(issued.getFormat());
        hist.setUid(user.getUid());
        hist.setRole(user.getRole());
        hist.setBrand(user.getBrand());
        hist.setDealerCode(user.getDealerCode());
        hist.setSourceSysId(req.getSourceSYSID());
        hist.setTargetSysId(req.getTargetSYSID());
        hist.setToken(issued.getToken());
        hist.setIssuedAt(issued.getIssuedAt());
        hist.setExpiresAt(issued.getExpiresAt());
        hist.setConsumed(false);
        tokenHistoryRepo.save(hist);

        audit.info("TOKEN_GENERATED", user.getUid(), req.getTargetSYSID(),
                Map.of("format", issued.getFormat(), "jti", issued.getJti()));

        PUBLISHOUT out = new PUBLISHOUT();
        out.setHtxtToken(issued.getToken());
        out.setUserID(user.getUid());
        out.setSourceSYSID(req.getSourceSYSID());
        out.setTargetSYSID(req.getTargetSYSID());
        out.setURLD(sys.getDirectReurlD());
        out.setURLM(sys.getDirectReurlM());
        out.setFormat(issued.getFormat());
        out.setJTI(issued.getJti());
        out.setERETURN(new Ereturn(IamCommentCodes.TYPE_SUCCESS, IamCommentCodes.MSG_SUCCESS));

        // Attach only the attributes that actually went into this specific token format
        java.util.Map<String, String> enriched = new java.util.LinkedHashMap<>();
        switch (format) {
            case IGTK -> {
                // IGTK is opaque (SHA-256 hash) but the callback validation returns these
                enriched.put("uid", user.getUid());
                enriched.put("first_name", user.getFirstName());
                enriched.put("last_name", user.getLastName());
                enriched.put("corporate_code", user.getCorporateCode());
                enriched.put("corporate_name", user.getCorporateName());
                enriched.put("job_code", user.getJobCode());
                enriched.put("job_title", user.getJobTitle());
                enriched.put("region_code", user.getRegionCode());
                enriched.put("sales_district", user.getSalesDistrict());
                enriched.put("service_district", user.getServiceDistrict());
                enriched.put("parts_district", user.getPartsDistrict());
                enriched.put("dealer_code", user.getDealerCode() != null ? user.getDealerCode() : "");
                enriched.put("dealer_state_code", user.getDealerStateCode());
                enriched.put("dealer_type_code", user.getDealerTypeCode());
                enriched.put("email", user.getEmail());
                enriched.put("access_level", user.getAccessLevel());
                enriched.put("permission_groups", user.getPermissionGroups());
            }
            case SAML -> {
                enriched.put("uid", user.getUid());
                enriched.put("jti", issued.getJti());
                enriched.put("role", user.getRole());
                enriched.put("brand", user.getBrand());
                enriched.put("dealer_code", user.getDealerCode() != null ? user.getDealerCode() : "");
                enriched.put("first_name", user.getFirstName());
                enriched.put("last_name", user.getLastName());
                enriched.put("email", user.getEmail());
                enriched.put("company", user.getCorporateName());
                enriched.put("zone", user.getZone());
                enriched.put("department", user.getDepartment());
            }
            case AES256, RC4 -> {
                enriched.put("uid", user.getUid());
                enriched.put("role", user.getRole());
                enriched.put("brand", user.getBrand());
                enriched.put("dealer_code", user.getDealerCode() != null ? user.getDealerCode() : "");
                enriched.put("first_name", user.getFirstName());
                enriched.put("last_name", user.getLastName());
                enriched.put("email", user.getEmail());
                enriched.put("timestamp", String.valueOf(java.time.Instant.now().toEpochMilli()));
            }
            case WPC_OTP -> {
                enriched.put("userid", "[AES-ECB encrypted uid]");
                enriched.put("otp", "[6-digit one-time password]");
                enriched.put("group", "GMA".equals(user.getBrand()) ? "G_DEALER_USA" : "H_DEALER_USA");
                enriched.put("region", "USA");
            }
            default -> {
                enriched.put("uid", user.getUid());
                enriched.put("role", user.getRole());
            }
        }
        out.setEnrichedAttributes(enriched);

        return out;
    }

    private PUBLISHOUT error(PARAMIN req, String message) {
        log.warn("[PublishToken] denied target={} uid={} reason={}",
                req.getTargetSYSID(), req.getUserID(), message);
        audit.security("PERMISSION_DENIED", req.getUserID(), req.getTargetSYSID(),
                Map.of("reason", message));
        PUBLISHOUT out = new PUBLISHOUT();
        out.setUserID(req.getUserID());
        out.setSourceSYSID(req.getSourceSYSID());
        out.setTargetSYSID(req.getTargetSYSID());
        out.setERETURN(new Ereturn(IamCommentCodes.TYPE_ERROR, message));
        return out;
    }

    /** Decode the launch token's middle segment to grab jti — matches sso-launch.js:51 */
    private static String decodeJti(String launchTokenRaw) {
        try {
            String[] parts = launchTokenRaw.split("\\.");
            if (parts.length < 2) return "";
            byte[] body = java.util.Base64.getUrlDecoder().decode(parts[1]);
            String json = new String(body, java.nio.charset.StandardCharsets.UTF_8);
            int idx = json.indexOf("\"jti\":\"");
            if (idx < 0) return "";
            int start = idx + 7;
            int end = json.indexOf('"', start);
            return end < 0 ? "" : json.substring(start, end);
        } catch (Exception e) {
            return "";
        }
    }

    private static String asString(Object o, String def) {
        return o == null ? def : String.valueOf(o);
    }
}
