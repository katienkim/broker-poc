package com.hma.idpbrokerservice.sso.endpoint;

import com.hma.idpbrokerservice.sso.contract.authenticateuserservice.AUTHIN;
import com.hma.idpbrokerservice.sso.contract.authenticateuserservice.AUTHOUT;
import com.hma.idpbrokerservice.sso.service.AuthenticateUserService;
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
public class AuthenticateUserEndpoint {

    private static final String NS = "http://hyundaidealer.com/AuthenticateUserService/";
    private final AuthenticateUserService service;

    @PayloadRoot(namespace = NS, localPart = "AuthenticateUser")
    @ResponsePayload
    public Source authenticate(@RequestPayload Source request) throws Exception {
        StringResult sr = new StringResult();
        TransformerFactory.newInstance().newTransformer().transform(request, sr);
        Document doc = XmlPayloadUtil.parse(sr.toString());
        Element root = doc.getDocumentElement();

        AUTHIN in = new AUTHIN();
        in.setToken(XmlPayloadUtil.text(root, "Token"));
        in.setFormat(XmlPayloadUtil.text(root, "Format"));
        in.setJTI(XmlPayloadUtil.text(root, "JTI"));

        AUTHOUT out = service.authenticate(in);

        String e = "<ERETURN>"
                + XmlPayloadUtil.tag("TYPE",    out.getERETURN() == null ? "E" : out.getERETURN().getTYPE())
                + XmlPayloadUtil.tag("MESSAGE", out.getERETURN() == null ? "" : out.getERETURN().getMESSAGE())
                + "</ERETURN>";

        String xml = "<AuthenticateUserResponse xmlns=\"" + NS + "\">"
                + XmlPayloadUtil.tag("Valid",      String.valueOf(out.isValid()))
                + XmlPayloadUtil.tag("UserID",     out.getUserID())
                + XmlPayloadUtil.tag("Role",       out.getRole())
                + XmlPayloadUtil.tag("Brand",      out.getBrand())
                + XmlPayloadUtil.tag("DealerCode", out.getDealerCode())
                + XmlPayloadUtil.tag("UserType",   out.getUserType())
                + XmlPayloadUtil.tag("Igtk",       out.getIgtk())
                + XmlPayloadUtil.tag("ExpiresAt",  out.getExpiresAt())
                + e
                + "</AuthenticateUserResponse>";
        return new StringSource(xml);
    }
}
