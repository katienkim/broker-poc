package com.hma.idpbrokerservice.sso.oidc.exception;

import lombok.Getter;

/** Raised when a state code can't be located or was previously consumed. */
@Getter
public class StateCodeNotFoundException extends RuntimeException {
    private final String errorCode = "STATE_CODE_NOT_FOUND";

    public StateCodeNotFoundException(String stateCode) {
        super("State code not found: " + stateCode);
    }
}
