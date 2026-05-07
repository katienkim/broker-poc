package com.hma.idpbrokerservice.sso.contract.otpvalidateservice;

import com.hma.idpbrokerservice.sso.contract.Ereturn;
import lombok.Data;

@Data
public class OTPOUT {
    private boolean Valid;
    private String UserID;
    private String Role;
    private String Brand;
    private String DealerCode;
    private Ereturn ERETURN;
    private com.hma.idpbrokerservice.sso.domain.UserContext userContext;
}
