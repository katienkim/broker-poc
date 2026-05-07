package com.hma.idpbrokerservice.sso.service.impl;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.constants.IamCommentCodes;
import com.hma.idpbrokerservice.sso.contract.Ereturn;
import com.hma.idpbrokerservice.sso.contract.adminrevokeservice.REVOKEIN;
import com.hma.idpbrokerservice.sso.contract.adminrevokeservice.REVOKEOUT;
import com.hma.idpbrokerservice.sso.entity.SsoRevocation;
import com.hma.idpbrokerservice.sso.repository.SsoRevocationRepository;
import com.hma.idpbrokerservice.sso.service.AdminRevokeService;
import com.hma.idpbrokerservice.sso.service.support.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;

/** Direct port of poc/apps/iam-broker/src/routes/revoke.js. 2-hour TTL preserved. */
@Service
@RequiredArgsConstructor
public class AdminRevokeServiceImpl implements AdminRevokeService {

    private static final long TTL_MS = 2 * 60 * 60 * 1000L;

    private final SsoRevocationRepository repo;
    private final SsoProperties properties;
    private final AuditService audit;

    @Override
    @Transactional
    public REVOKEOUT revoke(REVOKEIN req) {
        if (!properties.getAdmin().getApiKey().equals(req.getAdminKey())) {
            return error(IamCommentCodes.MSG_UNAUTHORIZED);
        }
        if (req.getReason() == null || req.getReason().isBlank()) {
            return error(IamCommentCodes.MSG_BAD_REQUEST);
        }
        if ((req.getTokenID() == null || req.getTokenID().isBlank())
                && (req.getUserID() == null || req.getUserID().isBlank())) {
            return error(IamCommentCodes.MSG_BAD_REQUEST);
        }

        Instant now = Instant.now();
        Instant exp = now.plusMillis(TTL_MS);

        if (req.getTokenID() != null && !req.getTokenID().isBlank()) {
            SsoRevocation r = new SsoRevocation();
            r.setId("token:" + req.getTokenID());
            r.setType("token"); r.setSubject(req.getTokenID());
            r.setReason(req.getReason()); r.setRevokedAt(now); r.setExpiresAt(exp);
            repo.save(r);
            audit.security("TOKEN_REVOKED", null, null,
                    Map.of("token_id", req.getTokenID(), "reason", req.getReason()));
            REVOKEOUT out = new REVOKEOUT();
            out.setRevoked(true); out.setType("token"); out.setID(req.getTokenID());
            out.setERETURN(new Ereturn(IamCommentCodes.TYPE_SUCCESS, IamCommentCodes.MSG_SUCCESS));
            return out;
        }

        SsoRevocation r = new SsoRevocation();
        r.setId("user:" + req.getUserID());
        r.setType("user"); r.setSubject(req.getUserID());
        r.setReason(req.getReason()); r.setRevokedAt(now); r.setExpiresAt(exp);
        repo.save(r);
        audit.security("USER_REVOKED", req.getUserID(), null,
                Map.of("reason", req.getReason()));
        REVOKEOUT out = new REVOKEOUT();
        out.setRevoked(true); out.setType("user"); out.setID(req.getUserID());
        out.setERETURN(new Ereturn(IamCommentCodes.TYPE_SUCCESS, IamCommentCodes.MSG_SUCCESS));
        return out;
    }

    private REVOKEOUT error(String message) {
        REVOKEOUT out = new REVOKEOUT();
        out.setRevoked(false);
        out.setERETURN(new Ereturn(IamCommentCodes.TYPE_ERROR, message));
        return out;
    }
}
