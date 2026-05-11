package com.hma.idpbrokerservice.sso.oidc.exception;

import lombok.Getter;

/** Raised for any id_token validation failure. {@link #errorCode} is for telemetry. */
@Getter
public class JwtValidationException extends RuntimeException {
    private final String errorCode;

    public JwtValidationException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }
}
