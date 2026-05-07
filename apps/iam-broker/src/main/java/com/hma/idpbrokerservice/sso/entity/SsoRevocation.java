package com.hma.idpbrokerservice.sso.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

/**
 * Token + user revocation. Direct port of poc/apps/iam-broker/src/lib/revocation-store.js.
 * type = "token" → revoke a single jti
 * type = "user"  → revoke all tokens issued before revoked_at for this uid
 */
@Data
@Entity
@Table(name = "ia_tb_sso_revocation")
public class SsoRevocation {

    @Id
    @Column(name = "id", length = 160)
    private String id;                  // composite "token:<jti>" or "user:<uid>"

    @Column(name = "type", length = 8)
    private String type;                // "token" | "user"

    @Column(name = "subject", length = 128)
    private String subject;             // jti or uid

    @Column(name = "reason", length = 256)
    private String reason;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;          // 2h after revoked_at; matches Node store TTL
}
