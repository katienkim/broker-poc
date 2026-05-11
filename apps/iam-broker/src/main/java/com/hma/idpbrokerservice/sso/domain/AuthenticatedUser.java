package com.hma.idpbrokerservice.sso.domain;

import lombok.Builder;
import lombok.Data;

import java.util.Collections;
import java.util.Map;

/**
 * Protocol-agnostic identity returned by both SAML SP and OIDC RP success
 * paths. The downstream code (PublishTokenService bridge, auto-submit HTML)
 * doesn't care which protocol produced the user.
 *
 * Mirrors the production
 * com.hma.idpbrokerservice.domain.model.AuthenticatedUser class.
 */
@Data
@Builder
public class AuthenticatedUser {
    /** OIDC `sub` claim or SAML NameID. The stable identifier. */
    private final String sub;

    /** OIDC `nonce` claim — null for SAML. */
    private final String nonce;

    /** Issuer entityID (OIDC iss / SAML Issuer). */
    private final String issuer;

    /** Either "oidc" or "saml" — useful for audit logs. */
    private final String source;

    /** All other claims / SAML attributes. Never null. */
    @Builder.Default
    private final Map<String, Object> attributes = Collections.emptyMap();
}
