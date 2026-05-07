package com.hma.idpbrokerservice.sso.endpoint;

import com.hma.idpbrokerservice.sso.contract.otpvalidateservice.OTPIN;
import com.hma.idpbrokerservice.sso.contract.otpvalidateservice.OTPOUT;
import com.hma.idpbrokerservice.sso.service.OtpValidateService;
import lombok.RequiredArgsConstructor;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;
import org.springframework.xml.transform.StringResult;
import org.springframework.xml.transform.StringSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.transform.Source;
import javax.xml.transform.TransformerFactory;

@Endpoint
@RequiredArgsConstructor
public class OtpValidateEndpoint {

    private static final String NS = "http://hyundaidealer.com/OtpValidateService/";
    private final OtpValidateService service;

    @PayloadRoot(namespace = NS, localPart = "OtpValidate")
    @ResponsePayload
    public Source validate(@RequestPayload Source request) throws Exception {
        StringResult sr = new StringResult();
        TransformerFactory.newInstance().newTransformer().transform(request, sr);
        Document doc = XmlPayloadUtil.parse(sr.toString());
        Element root = doc.getDocumentElement();

        OTPIN in = new OTPIN();
        in.setUserID(XmlPayloadUtil.text(root, "UserID"));
        in.setOtp(XmlPayloadUtil.text(root, "Otp"));

        OTPOUT out = service.validate(in);

        String e = "<ERETURN>"
                + XmlPayloadUtil.tag("TYPE",    out.getERETURN() == null ? "E" : out.getERETURN().getTYPE())
                + XmlPayloadUtil.tag("MESSAGE", out.getERETURN() == null ? "" : out.getERETURN().getMESSAGE())
                + "</ERETURN>";

        String xml = "<OtpValidateResponse xmlns=\"" + NS + "\">"
                + XmlPayloadUtil.tag("Valid",      String.valueOf(out.isValid()))
                + XmlPayloadUtil.tag("UserID",     out.getUserID())
                + XmlPayloadUtil.tag("Role",       out.getRole())
                + XmlPayloadUtil.tag("Brand",      out.getBrand())
                + XmlPayloadUtil.tag("DealerCode", out.getDealerCode())
                + e
                + "</OtpValidateResponse>";
        return new StringSource(xml);
    }
}
