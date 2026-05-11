package com.hma.idpbrokerservice.sso.oidc.dto;

import com.hma.idpbrokerservice.sso.entity.OAuthState;
import lombok.Builder;
import lombok.Data;

/** Result of validating a state code — either a valid {@link OAuthState} or an error. */
@Data
@Builder
public class StateCodeValidationResult {
    private final boolean valid;
    private final OAuthState oauthState;
    private final String errorCode;
    private final String errorMessage;

    public static StateCodeValidationResult success(OAuthState state) {
        return StateCodeValidationResult.builder().valid(true).oauthState(state).build();
    }

    public static StateCodeValidationResult failure(String message, String code) {
        return StateCodeValidationResult.builder()
                .valid(false).errorMessage(message).errorCode(code).build();
    }
}
