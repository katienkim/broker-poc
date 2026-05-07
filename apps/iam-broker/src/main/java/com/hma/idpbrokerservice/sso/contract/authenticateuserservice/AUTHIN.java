package com.hma.idpbrokerservice.sso.contract.authenticateuserservice;

import lombok.Data;

@Data
public class AUTHIN {
    private String Token;
    private String Format;
    private String JTI;
}
