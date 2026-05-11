package com.hma.idpbrokerservice.sso.service;

import com.hma.idpbrokerservice.sso.entity.InboundSamlAssertionSeen;
import com.hma.idpbrokerservice.sso.repository.InboundSamlAssertionSeenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Records every accepted AssertionID in the DB and rejects repeats. Spring
 * Security SAML2 validates signature + NotOnOrAfter + AudienceRestriction but
 * has no concept of "I've seen this exact AssertionID already."
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InboundSamlReplayGuard {

    private final InboundSamlAssertionSeenRepository repo;

    /**
     * @throws ReplayDetectedException if this AssertionID has been processed before
     */
    @Transactional
    public void recordOrThrow(String assertionId, String issuer, String subject, Instant notOnOrAfter) {
        if (assertionId == null || assertionId.isBlank()) {
            throw new IllegalArgumentException("AssertionID cannot be blank");
        }
        try {
            repo.save(InboundSamlAssertionSeen.builder()
                    .assertionId(assertionId)
                    .issuer(issuer)
                    .subject(subject)
                    .seenAt(Instant.now())
                    .expiresAt(notOnOrAfter != null
                            ? notOnOrAfter
                            : Instant.now().plusSeconds(300))
                    .build());
        } catch (DataIntegrityViolationException e) {
            log.warn("[SamlReplay] AssertionID {} already seen — rejecting replay", assertionId);
            throw new ReplayDetectedException(assertionId);
        }
    }

    public static class ReplayDetectedException extends RuntimeException {
        public ReplayDetectedException(String assertionId) {
            super("SAML assertion replay detected: " + assertionId);
        }
    }
}
