package com.hma.idpbrokerservice.sso.repository;

import com.hma.idpbrokerservice.sso.entity.SsoBypass;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;

public interface SsoBypassRepository extends JpaRepository<SsoBypass, String> {

    Optional<SsoBypass> findFirstByUserIdAndTargetSystemAndExpiresAtAfter(
            String userId, String targetSystem, Instant now);
}
