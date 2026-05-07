package com.hma.idpbrokerservice.sso.contract.otpvalidateservice;

import lombok.Data;

@Data
public class OTPIN {
    private String UserID;
    private String Otp;
}
