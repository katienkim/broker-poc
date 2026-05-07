package com.hma.idpbrokerservice.sso.service;

import com.hma.idpbrokerservice.sso.contract.adminbypassservice.BYPASSIN;
import com.hma.idpbrokerservice.sso.contract.adminbypassservice.BYPASSOUT;

public interface AdminBypassService {
    BYPASSOUT execute(BYPASSIN request);
}
