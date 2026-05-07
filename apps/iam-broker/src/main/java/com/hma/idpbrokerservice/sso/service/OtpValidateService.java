package com.hma.idpbrokerservice.sso.service;

import com.hma.idpbrokerservice.sso.contract.otpvalidateservice.OTPIN;
import com.hma.idpbrokerservice.sso.contract.otpvalidateservice.OTPOUT;

public interface OtpValidateService {
    OTPOUT validate(OTPIN request);
}
