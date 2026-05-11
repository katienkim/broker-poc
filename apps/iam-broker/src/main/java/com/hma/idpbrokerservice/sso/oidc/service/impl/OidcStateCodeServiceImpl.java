package com.hma.idpbrokerservice.sso.oidc.service.impl;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.entity.OAuthState;
import com.hma.idpbrokerservice.sso.oidc.dto.StateCodeValidationResult;
import com.hma.idpbrokerservice.sso.oidc.exception.StateCodeNotFoundException;
import com.hma.idpbrokerservice.sso.oidc.service.OidcStateCodeService;
import com.hma.idpbrokerservice.sso.repository.OAuthStateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * Combines production's IStateCodeGenerator + IStateCodeValidator + IStateCodeService
 * into a single service. State codes are 256-bit URL-safe randoms; nonces are
 * separate 128-bit randoms. Both checked on callback (state by lookup, nonce
 * by comparison against id_token claim).
 */
@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class OidcStateCodeServiceImpl implements OidcStateCodeService {

    private static final SecureRandom RNG = new SecureRandom();

    private final OAuthStateRepository repo;
    private final SsoProperties properties;

    @Override
    public OAuthState createStateCode(
            String targetVendor,
            String applicationParameter,
            String userIp,
            String userAgent) {

        SsoProperties.Oidc.Pid cfg = properties.getOidc().getPid();
        Instant now = Instant.now();

        OAuthState state = OAuthState.builder()
                .stateCode(randomBase64Url(32))
                .nonce(randomBase64Url(16))
                .flow("oidc")
                .targetVendor(targetVendor)
                .applicationParameter(applicationParameter)
                .userIp(userIp)
                .userAgent(userAgent)
                .used(false)
                .createdAt(now)
                .expiresAt(now.plusSeconds(60L * cfg.getStateCodeExpiryMinutes()))
                .build();

        OAuthState saved = repo.save(state);
        log.info("[OIDC] state code created — stateCode={} targetVendor={}",
                saved.getStateCode(), targetVendor);
        return saved;
    }

    @Override
    public StateCodeValidationResult validateStateCode(String stateCode) {
        if (stateCode == null || stateCode.isBlank()) {
            return StateCodeValidationResult.failure("State code cannot be blank", "BLANK_STATE_CODE");
        }
        Optional<OAuthState> opt = repo.findById(stateCode);
        if (opt.isEmpty()) {
            return StateCodeValidationResult.failure("State code not found", "STATE_CODE_NOT_FOUND");
        }
        OAuthState state = opt.get();
        if (state.isUsed()) {
            return StateCodeValidationResult.failure("State code already used", "STATE_CODE_USED");
        }
        if (Instant.now().isAfter(state.getExpiresAt())) {
            return StateCodeValidationResult.failure("State code expired", "STATE_CODE_EXPIRED");
        }
        if (!"oidc".equals(state.getFlow())) {
            return StateCodeValidationResult.failure(
                    "State code is not for OIDC flow", "STATE_CODE_WRONG_FLOW");
        }
        return StateCodeValidationResult.success(state);
    }

    @Override
    public void markStateCodeAsUsed(String stateCode) throws StateCodeNotFoundException {
        OAuthState state = repo.findById(stateCode)
                .orElseThrow(() -> new StateCodeNotFoundException(stateCode));
        state.setUsed(true);
        repo.save(state);
    }

    private static String randomBase64Url(int bytes) {
        byte[] buf = new byte[bytes];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
