package com.hma.idpbrokerservice.sso.oidc.service;

import com.hma.idpbrokerservice.sso.entity.OAuthState;
import com.hma.idpbrokerservice.sso.oidc.dto.StateCodeValidationResult;
import com.hma.idpbrokerservice.sso.oidc.exception.StateCodeNotFoundException;

public interface OidcStateCodeService {
    OAuthState createStateCode(
            String targetVendor,
            String applicationParameter,
            String userIp,
            String userAgent);

    StateCodeValidationResult validateStateCode(String stateCode);

    void markStateCodeAsUsed(String stateCode) throws StateCodeNotFoundException;
}
