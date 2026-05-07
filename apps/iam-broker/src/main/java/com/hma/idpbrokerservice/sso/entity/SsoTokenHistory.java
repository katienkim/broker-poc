package com.hma.idpbrokerservice.sso.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

/**
 * One row per issued token. Replaces the in-memory tokenRegistry from
 * poc/apps/iam-broker/src/lib/token-registry.js. consumed flips on first
 * AuthenticateUser call → second call returns ALREADY_USED.
 *
 * For IGTK we also store the canonical hash string (token_hash) separately
 * so AuthenticateUser can look up by either jti or hash.
 */
@Data
@Entity
@Table(name = "ia_tb_sso_token_h", indexes = {
        @Index(name = "ix_token_history_token", columnList = "token"),
        @Index(name = "ix_token_history_uid",   columnList = "uid")
})
public class SsoTokenHistory {

    @Id
    @Column(name = "jti", length = 64)
    private String jti;                  // single-use identifier (UUID)

    @Column(name = "format", length = 16)
    private String format;               // TokenFormat code

    @Column(name = "uid", length = 128)
    private String uid;                  // user the token was issued for

    @Column(name = "role", length = 64)
    private String role;
    @Column(name = "brand", length = 16)
    private String brand;
    @Column(name = "dealer_code", length = 32)
    private String dealerCode;

    @Column(name = "source_sys_id", length = 64)
    private String sourceSysId;          // who is asking (e.g. dealers portal)
    @Column(name = "target_sys_id", length = 64)
    private String targetSysId;          // who the token is for

    @Column(name = "token", columnDefinition = "text")
    private String token;                // full opaque token string (JWT-less for IGTK; XML/base64 for SAML; etc.)

    @Column(name = "issued_at")
    private Instant issuedAt;
    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "consumed")
    private Boolean consumed;            // single-use flip; true after AuthenticateUser succeeds
    @Column(name = "consumed_at")
    private Instant consumedAt;
}
