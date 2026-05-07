package com.hma.idpbrokerservice.sso.contract.adminrevokeservice;

import com.hma.idpbrokerservice.sso.contract.Ereturn;
import lombok.Data;

@Data
public class REVOKEOUT {
    private boolean Revoked;
    private String Type;     // "token" | "user"
    private String ID;
    private Ereturn ERETURN;
}
