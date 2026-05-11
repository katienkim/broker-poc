package com.hma.idpbrokerservice.sso.oidc.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Mapped response from POST /token at HMG Partner ID. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenResponse {

    @JsonProperty("access_token") private String accessToken;
    @JsonProperty("id_token")     private String idToken;
    @JsonProperty("refresh_token") private String refreshToken;
    @JsonProperty("token_type")   private String tokenType;
    @JsonProperty("expires_in")   private int expiresIn;
    @JsonProperty("scope")        private String scope;
}
