package com.hma.idpbrokerservice.sso.service.impl;

import com.hma.idpbrokerservice.sso.constants.IamCommentCodes;
import com.hma.idpbrokerservice.sso.contract.Ereturn;
import com.hma.idpbrokerservice.sso.contract.authenticateuserservice.AUTHIN;
import com.hma.idpbrokerservice.sso.contract.authenticateuserservice.AUTHOUT;
import com.hma.idpbrokerservice.sso.entity.SsoRevocation;
import com.hma.idpbrokerservice.sso.entity.SsoTokenHistory;
import com.hma.idpbrokerservice.sso.repository.SsoRevocationRepository;
import com.hma.idpbrokerservice.sso.repository.SsoTokenHistoryRepository;
import com.hma.idpbrokerservice.sso.service.AuthenticateUserService;
import com.hma.idpbrokerservice.sso.service.support.AuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * Vendor-side validation. Replaces poc/apps/iam-broker/src/routes/token.js
 * (POST /token/validate + POST /token/consume) with one SOAP round-trip.
 *
 * Single-use is enforced by atomically flipping `consumed=true` on the
 * token-history row — same semantics as tokenRegistry.consume() in Node, but
 * persisted, so restarts don't lose state.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticateUserServiceImpl implements AuthenticateUserService {

    private final SsoTokenHistoryRepository tokenHistoryRepo;
    private final SsoRevocationRepository revocationRepo;
    private final AuditService audit;

    @Override
    @Transactional
    public AUTHOUT authenticate(AUTHIN req) {
        log.info("[AuthenticateUser] format={} jti={}", req.getFormat(), req.getJTI());

        Optional<SsoTokenHistory> rowOpt =
                req.getJTI() != null && !req.getJTI().isBlank()
                        ? tokenHistoryRepo.findById(req.getJTI())
                        : tokenHistoryRepo.findByToken(req.getToken());

        if (rowOpt.isEmpty()) return error(IamCommentCodes.MSG_TOKEN_NOT_FOUND);
        SsoTokenHistory row = rowOpt.get();

        Instant now = Instant.now();
        if (row.getExpiresAt() != null && now.isAfter(row.getExpiresAt())) {
            return error(IamCommentCodes.MSG_TOKEN_EXPIRED);
        }

        // revocation check
        if (revocationRepo.findById("token:" + row.getJti()).filter(r -> now.isBefore(r.getExpiresAt())).isPresent()) {
            return error(IamCommentCodes.MSG_TOKEN_REVOKED);
        }
        Optional<SsoRevocation> userRev = revocationRepo.findById("user:" + row.getUid());
        if (userRev.isPresent() && now.isBefore(userRev.get().getExpiresAt())
                && row.getIssuedAt() != null
                && row.getIssuedAt().isBefore(userRev.get().getRevokedAt())) {
            return error(IamCommentCodes.MSG_USER_REVOKED);
        }

        // single-use flip
        int updated = tokenHistoryRepo.markConsumed(row.getJti(), now);
        if (updated == 0) {
            audit.security("TOKEN_REPLAY", row.getUid(), row.getTargetSysId(),
                    java.util.Map.of("jti", row.getJti()));
            return error(IamCommentCodes.MSG_TOKEN_ALREADY_USED);
        }

        audit.info("TOKEN_CONSUMED", row.getUid(), row.getTargetSysId(),
                java.util.Map.of("jti", row.getJti(), "format", row.getFormat()));

        AUTHOUT out = new AUTHOUT();
        out.setValid(true);
        out.setUserID(row.getUid());
        out.setRole(row.getRole());
        out.setBrand(row.getBrand());
        out.setDealerCode(row.getDealerCode());
        out.setUserType("PID");
        out.setIgtk("igtk".equals(row.getFormat()) ? row.getToken() : null);
        out.setExpiresAt(row.getExpiresAt() == null ? null : row.getExpiresAt().toString());
        out.setERETURN(new Ereturn(IamCommentCodes.TYPE_SUCCESS, IamCommentCodes.MSG_SUCCESS));
        return out;
    }

    private AUTHOUT error(String message) {
        AUTHOUT out = new AUTHOUT();
        out.setValid(false);
        out.setERETURN(new Ereturn(IamCommentCodes.TYPE_ERROR, message));
        return out;
    }
}
