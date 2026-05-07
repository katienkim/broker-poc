package com.hma.idpbrokerservice.sso.contract.adminrevokeservice;

import lombok.Data;

@Data
public class REVOKEIN {
    private String AdminKey;
    private String TokenID;
    private String UserID;
    private String Reason;
}
