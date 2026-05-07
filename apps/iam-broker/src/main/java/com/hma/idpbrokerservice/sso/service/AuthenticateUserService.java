package com.hma.idpbrokerservice.sso.service;

import com.hma.idpbrokerservice.sso.contract.authenticateuserservice.AUTHIN;
import com.hma.idpbrokerservice.sso.contract.authenticateuserservice.AUTHOUT;

public interface AuthenticateUserService {
    AUTHOUT authenticate(AUTHIN request);
}
