package com.hma.idpbrokerservice.sso.oidc.service;

import com.hma.idpbrokerservice.sso.domain.AuthenticatedUser;

/**
 * Validates a JWT id_token and returns the authenticated principal.
 * Throws {@link com.hma.idpbrokerservice.sso.oidc.exception.JwtValidationException}
 * on any failure (bad alg, bad sig, expired, wrong iss/aud, missing sub).
 */
public interface JwtValidator {
    AuthenticatedUser validate(String token);
}
