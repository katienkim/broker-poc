package com.hma.idpbrokerservice.sso.repository;

import com.hma.idpbrokerservice.sso.entity.SsoTokenHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface SsoTokenHistoryRepository extends JpaRepository<SsoTokenHistory, String> {

    Optional<SsoTokenHistory> findByToken(String token);

    /**
     * Atomic single-use flip. Mirrors the semantics of
     * tokenRegistry.consume(id) in poc/apps/iam-broker/src/lib/token-registry.js:
     *   first call → 1 row updated → consumed=true
     *   second call (or unknown id) → 0 rows → caller returns ALREADY_USED.
     */
    @Modifying
    @Query("update SsoTokenHistory t set t.consumed = true, t.consumedAt = :now " +
           "where t.jti = :jti and (t.consumed is null or t.consumed = false) and t.expiresAt > :now")
    int markConsumed(@Param("jti") String jti, @Param("now") Instant now);
}
