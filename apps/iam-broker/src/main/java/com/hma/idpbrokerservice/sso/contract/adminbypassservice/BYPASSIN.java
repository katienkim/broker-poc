package com.hma.idpbrokerservice.sso.contract.adminbypassservice;

import lombok.Data;

@Data
public class BYPASSIN {
    private String Action;          // "create" | "cancel"
    private String AdminKey;
    private String AdminMfa;        // "true" required for create
    private String BypassID;        // for cancel
    private String UserID;          // for create
    private String TargetSystem;    // for create
    private Integer DurationMinutes;
    private String Justification;
}
