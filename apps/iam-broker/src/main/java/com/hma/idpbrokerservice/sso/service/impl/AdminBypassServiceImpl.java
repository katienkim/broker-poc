package com.hma.idpbrokerservice.sso.service.impl;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.constants.IamCommentCodes;
import com.hma.idpbrokerservice.sso.contract.Ereturn;
import com.hma.idpbrokerservice.sso.contract.adminbypassservice.BYPASSIN;
import com.hma.idpbrokerservice.sso.contract.adminbypassservice.BYPASSOUT;
import com.hma.idpbrokerservice.sso.entity.SsoBypass;
import com.hma.idpbrokerservice.sso.repository.SsoBypassRepository;
import com.hma.idpbrokerservice.sso.service.AdminBypassService;
import com.hma.idpbrokerservice.sso.service.support.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Direct port of poc/apps/iam-broker/src/routes/bypass.js. */
@Service
@RequiredArgsConstructor
public class AdminBypassServiceImpl implements AdminBypassService {

    private final SsoBypassRepository repo;
    private final SsoProperties properties;
    private final AuditService audit;

    @Override
    @Transactional
    public BYPASSOUT execute(BYPASSIN req) {
        if (!properties.getAdmin().getApiKey().equals(req.getAdminKey())) {
            return error(IamCommentCodes.MSG_UNAUTHORIZED);
        }

        if ("create".equalsIgnoreCase(req.getAction())) {
            if (properties.getAdmin().isRequireMfaHeader() && !"true".equalsIgnoreCase(req.getAdminMfa())) {
                return error(IamCommentCodes.MSG_MFA_REQUIRED);
            }
            if (req.getUserID() == null || req.getTargetSystem() == null
                    || req.getDurationMinutes() == null || req.getJustification() == null) {
                return error(IamCommentCodes.MSG_BAD_REQUEST);
            }

            int duration = Math.min(req.getDurationMinutes(),
                    properties.getBypass().getMaxDurationMinutes());

            SsoBypass entry = new SsoBypass();
            entry.setBypassId(UUID.randomUUID().toString());
            entry.setUserId(req.getUserID());
            entry.setTargetSystem(req.getTargetSystem());
            entry.setJustification(req.getJustification());
            entry.setCreatedBy("admin");
            entry.setCreatedAt(Instant.now());
            entry.setExpiresAt(Instant.now().plusSeconds(duration * 60L));
            repo.save(entry);

            audit.security("BYPASS_CREATED", req.getUserID(), req.getTargetSystem(),
                    Map.of("bypass_id", entry.getBypassId(),
                           "duration_minutes", duration,
                           "justification", req.getJustification()));

            BYPASSOUT out = new BYPASSOUT();
            out.setBypassID(entry.getBypassId());
            out.setUserID(entry.getUserId());
            out.setTargetSystem(entry.getTargetSystem());
            out.setExpiresAt(entry.getExpiresAt().toString());
            out.setERETURN(new Ereturn(IamCommentCodes.TYPE_SUCCESS, IamCommentCodes.MSG_SUCCESS));
            return out;
        }

        if ("cancel".equalsIgnoreCase(req.getAction())) {
            if (req.getBypassID() == null || req.getBypassID().isBlank()) {
                return error(IamCommentCodes.MSG_BAD_REQUEST);
            }
            Optional<SsoBypass> existing = repo.findById(req.getBypassID());
            if (existing.isEmpty()) return error(IamCommentCodes.MSG_BAD_REQUEST);
            repo.deleteById(req.getBypassID());

            audit.security("BYPASS_CANCELLED",
                    existing.get().getUserId(), existing.get().getTargetSystem(),
                    Map.of("bypass_id", req.getBypassID()));

            BYPASSOUT out = new BYPASSOUT();
            out.setBypassID(req.getBypassID());
            out.setCancelled(true);
            out.setERETURN(new Ereturn(IamCommentCodes.TYPE_SUCCESS, IamCommentCodes.MSG_SUCCESS));
            return out;
        }

        return error(IamCommentCodes.MSG_BAD_REQUEST);
    }

    private BYPASSOUT error(String message) {
        BYPASSOUT out = new BYPASSOUT();
        out.setERETURN(new Ereturn(IamCommentCodes.TYPE_ERROR, message));
        return out;
    }
}
