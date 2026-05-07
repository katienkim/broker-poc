package com.hma.idpbrokerservice.sso.contract.publishtokenservice;

import com.hma.idpbrokerservice.sso.contract.Ereturn;
import lombok.Data;

@Data
public class PUBLISHOUT {
    private String htxtToken;
    private String UserID;
    private String SourceSYSID;
    private String TargetSYSID;
    private Ereturn ERETURN;
    private String URLD;
    private String URLM;
    private String Format;
    private String JTI;
    // For dashboard display — the enriched attributes embedded in the token
    private java.util.Map<String, String> enrichedAttributes;
}
