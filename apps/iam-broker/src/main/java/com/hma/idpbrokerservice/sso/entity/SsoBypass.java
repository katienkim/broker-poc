package com.hma.idpbrokerservice.sso.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

/**
 * Active emergency-bypass entries. Port of poc/apps/iam-broker/src/lib/bypass-store.js.
 * Even though the broker no longer enforces user-level permissions (per Yoonmi /
 * Ahn Dae Hyun: user validation is owned by Dealers), keeping the bypass table
 * lets ops record "this user got an exception today, here's why" — which is
 * what the original feature was actually for.
 */
@Data
@Entity
@Table(name = "ia_tb_sso_bypass")
public class SsoBypass {

    @Id
    @Column(name = "bypass_id", length = 64)
    private String bypassId;

    @Column(name = "user_id", length = 128)
    private String userId;

    @Column(name = "target_system", length = 64)
    private String targetSystem;

    @Column(name = "justification", length = 512)
    private String justification;

    @Column(name = "created_by", length = 128)
    private String createdBy;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "expires_at")
    private Instant expiresAt;
}
