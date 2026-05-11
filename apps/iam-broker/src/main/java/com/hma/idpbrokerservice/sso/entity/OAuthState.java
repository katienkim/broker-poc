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
 * Server-side state for SP-initiated SSO. The opaque {@code stateCode} is
 * what's sent through the IdP round-trip (as OIDC {@code state} or SAML
 * {@code RelayState}); the row recovers {@code targetVendor} + {@code nonce}
 * on callback without trusting the client.
 *
 * Mirrors the production OAuthState entity in
 * iam-broker-poc/idp-ui-feature-Admin_System_Configuration/backend.
 */
@Entity
@Table(name = "ia_tb_oauth_state")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuthState {

    @Id
    @Column(name = "state_code", length = 128)
    private String stateCode;

    @Column(name = "nonce", length = 128)
    private String nonce;

    @Column(name = "flow", nullable = false, length = 16)
    private String flow;

    @Column(name = "target_vendor", length = 64)
    private String targetVendor;

    @Column(name = "source_system", length = 64)
    private String sourceSystem;

    @Column(name = "application_parameter", length = 256)
    private String applicationParameter;

    @Column(name = "user_ip", length = 64)
    private String userIp;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "used", nullable = false)
    private boolean used;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
