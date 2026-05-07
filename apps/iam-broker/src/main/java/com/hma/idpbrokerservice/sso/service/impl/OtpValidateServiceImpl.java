package com.hma.idpbrokerservice.sso.service.impl;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.constants.IamCommentCodes;
import com.hma.idpbrokerservice.sso.contract.Ereturn;
import com.hma.idpbrokerservice.sso.contract.otpvalidateservice.OTPIN;
import com.hma.idpbrokerservice.sso.contract.otpvalidateservice.OTPOUT;
import com.hma.idpbrokerservice.sso.domain.UserContext;
import com.hma.idpbrokerservice.sso.service.OtpValidateService;
import com.hma.idpbrokerservice.sso.service.support.AuditService;
import com.hma.idpbrokerservice.sso.service.support.OtpStore;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Direct port of poc/apps/iam-broker/src/routes/otp.js, including the
 * 3-strike lockout window. State is in-memory (map per uid) — same as Node.
 */
@Service
@RequiredArgsConstructor
public class OtpValidateServiceImpl implements OtpValidateService {

    private final OtpStore otpStore;
    private final AuditService audit;
    private final SsoProperties properties;

    private static final class Lockout {
        int failures;
        long windowStart;
        Long lockedUntil;
    }
    private final ConcurrentHashMap<String, Lockout> lockouts = new ConcurrentHashMap<>();

    @Override
    public OTPOUT validate(OTPIN req) {
        String uid = req.getUserID();
        String otp = req.getOtp();
        long now = System.currentTimeMillis();

        if (uid == null || uid.isBlank() || otp == null || otp.isBlank()) {
            return error(IamCommentCodes.MSG_BAD_REQUEST);
        }

        Lockout l = lockouts.get(uid);
        if (l != null && l.lockedUntil != null && now < l.lockedUntil) {
            audit.warn("RATE_LIMITED", uid, null, Map.of("scope", "otp_lockout"));
            return error(IamCommentCodes.MSG_OTP_LOCKED);
        }

        Optional<UserContext> userOpt = otpStore.consume(otp);
        if (userOpt.isPresent()) {
            lockouts.remove(uid);
            UserContext u = userOpt.get();
            OTPOUT out = new OTPOUT();
            out.setValid(true);
            out.setUserID(u.getUid());
            out.setRole(u.getRole());
            out.setBrand(u.getBrand());
            out.setDealerCode(u.getDealerCode());
            out.setUserContext(u);
            out.setERETURN(new Ereturn(IamCommentCodes.TYPE_SUCCESS, IamCommentCodes.MSG_SUCCESS));
            return out;
        }

        Lockout entry = lockouts.computeIfAbsent(uid, k -> new Lockout());
        long windowMs = properties.getRateLimit().getOtp().getLockoutWindowMs();
        if (entry.windowStart == 0 || now - entry.windowStart > windowMs) {
            entry.failures = 0;
            entry.windowStart = now;
        }
        entry.failures++;
        if (entry.failures >= properties.getRateLimit().getOtp().getLockoutFailures()) {
            entry.lockedUntil = now + properties.getRateLimit().getOtp().getLockoutDurationMs();
            audit.security("RATE_LIMITED", uid, null,
                    Map.of("scope", "otp_lockout", "failures", entry.failures));
        }
        return error(IamCommentCodes.MSG_OTP_INVALID);
    }

    private OTPOUT error(String message) {
        OTPOUT out = new OTPOUT();
        out.setValid(false);
        out.setERETURN(new Ereturn(IamCommentCodes.TYPE_ERROR, message));
        return out;
    }
}
