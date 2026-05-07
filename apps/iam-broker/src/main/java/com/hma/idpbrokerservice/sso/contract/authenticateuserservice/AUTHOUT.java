package com.hma.idpbrokerservice.sso.contract.authenticateuserservice;

import com.hma.idpbrokerservice.sso.contract.Ereturn;
import lombok.Data;

@Data
public class AUTHOUT {
    private boolean Valid;
    private String UserID;
    private String Role;
    private String Brand;
    private String DealerCode;
    private String UserType;
    private String Igtk;
    private String ExpiresAt;
    private Ereturn ERETURN;
}
