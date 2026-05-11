package com.hma.idpbrokerservice.sso.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Replay defense — one row per AssertionID validated by the SAML SP. Insert
 * succeeds only the first time; PK conflict on retry signals replay.
 */
@Entity
@Table(name = "ia_tb_inbound_saml_assertion_seen")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InboundSamlAssertionSeen {

    @Id
    @Column(name = "assertion_id", length = 256)
    private String assertionId;

    @Column(name = "issuer", nullable = false, length = 256)
    private String issuer;

    @Column(name = "subject", length = 256)
    private String subject;

    @Column(name = "seen_at", nullable = false)
    private Instant seenAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
