package com.hma.idpbrokerservice.sso.contract.publishtokenservice;

import lombok.Data;

/** PublishToken request POJO. Field names match the XSD elements verbatim. */
@Data
public class PARAMIN {
    private String LaunchToken;
    private String SourceSYSID;
    private String TargetSYSID;
    private String UserID;
    private String CompanyCode;
    private String FlowID;
}
