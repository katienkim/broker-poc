package com.hma.idpbrokerservice.sso.oidc.service;

import com.hma.idpbrokerservice.sso.oidc.dto.TokenResponse;

/** Exchanges an OAuth2 authorization code for id_token + access_token + refresh_token. */
public interface TokenExchangeService {
    TokenResponse exchangeCodeForTokens(String authorizationCode);
}
