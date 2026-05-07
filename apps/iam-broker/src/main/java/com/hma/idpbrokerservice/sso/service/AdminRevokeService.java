package com.hma.idpbrokerservice.sso.service;

import com.hma.idpbrokerservice.sso.contract.adminrevokeservice.REVOKEIN;
import com.hma.idpbrokerservice.sso.contract.adminrevokeservice.REVOKEOUT;

public interface AdminRevokeService {
    REVOKEOUT revoke(REVOKEIN request);
}
