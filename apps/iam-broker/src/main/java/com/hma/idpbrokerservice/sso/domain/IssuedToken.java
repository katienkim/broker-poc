package com.hma.idpbrokerservice.sso.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

/** Carrier returned from each token generator. */
@Data
@Builder
@AllArgsConstructor
public class IssuedToken {
    private String token;       // the opaque string the vendor receives
    private String format;      // TokenFormat.code()
    private String jti;
    private Instant issuedAt;
    private Instant expiresAt;
}
