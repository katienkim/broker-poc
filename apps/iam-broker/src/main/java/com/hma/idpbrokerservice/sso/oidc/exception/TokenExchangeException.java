package com.hma.idpbrokerservice.sso.oidc.exception;

import lombok.Getter;

/** Raised when the OIDC token endpoint exchange fails (4xx, 5xx, parse error). */
@Getter
public class TokenExchangeException extends RuntimeException {
    private final String errorCode;

    public TokenExchangeException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public TokenExchangeException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }
}
