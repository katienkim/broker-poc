package com.hma.idpbrokerservice.sso.contract.adminbypassservice;

import com.hma.idpbrokerservice.sso.contract.Ereturn;
import lombok.Data;

@Data
public class BYPASSOUT {
    private String BypassID;
    private String UserID;
    private String TargetSystem;
    private String ExpiresAt;
    private Boolean Cancelled;
    private Ereturn ERETURN;
}
