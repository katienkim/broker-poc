package com.hma.idpbrokerservice.sso.oidc.service.impl;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.oidc.dto.TokenResponse;
import com.hma.idpbrokerservice.sso.oidc.exception.TokenExchangeException;
import com.hma.idpbrokerservice.sso.oidc.service.TokenExchangeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

/**
 * Ports production TokenServiceImpl. Uses {@link WebClient} (already in the
 * broker via {@code WebClient.Builder}) instead of production's {@code RestClient}
 * — same semantics, fewer new beans.
 */
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(name = "sso.oidc.pid.enabled", havingValue = "true")
@Slf4j
public class TokenExchangeServiceImpl implements TokenExchangeService {

    private final WebClient.Builder webClientBuilder;
    private final SsoProperties properties;

    @Override
    public TokenResponse exchangeCodeForTokens(String authorizationCode) {
        SsoProperties.Oidc.Pid cfg = properties.getOidc().getPid();
        log.info("[OIDC] exchanging authorization code at {}", cfg.getTokenEndpoint());

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", authorizationCode);
        form.add("redirect_uri", cfg.getRedirectUri());
        form.add("client_id", cfg.getClientId());
        form.add("client_secret", cfg.getClientSecret());

        try {
            TokenResponse resp = webClientBuilder.build().post()
                    .uri(cfg.getTokenEndpoint())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromFormData(form))
                    .retrieve()
                    .bodyToMono(TokenResponse.class)
                    .block();

            if (resp == null || resp.getIdToken() == null) {
                throw new TokenExchangeException(
                        "Token endpoint returned an empty or invalid response",
                        "TOKEN_EXCHANGE_EMPTY_RESPONSE");
            }
            return resp;

        } catch (TokenExchangeException e) {
            throw e;
        } catch (WebClientResponseException e) {
            log.error("[OIDC] token endpoint HTTP error: status={}, body={}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            String code = e.getStatusCode().is4xxClientError()
                    ? "TOKEN_EXCHANGE_CLIENT_ERROR" : "TOKEN_EXCHANGE_SERVER_ERROR";
            throw new TokenExchangeException(
                    "Token exchange failed with status " + e.getStatusCode(), code, e);
        } catch (Exception e) {
            log.error("[OIDC] unexpected error during token exchange", e);
            throw new TokenExchangeException(
                    "Token exchange failed unexpectedly", "TOKEN_EXCHANGE_ERROR", e);
        }
    }
}
