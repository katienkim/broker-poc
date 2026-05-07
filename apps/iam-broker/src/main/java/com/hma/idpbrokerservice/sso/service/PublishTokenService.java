package com.hma.idpbrokerservice.sso.service;

import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PARAMIN;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PUBLISHOUT;

public interface PublishTokenService {
    PUBLISHOUT createToken(PARAMIN request);
}
