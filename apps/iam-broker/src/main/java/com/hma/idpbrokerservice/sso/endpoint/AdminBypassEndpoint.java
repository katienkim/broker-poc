package com.hma.idpbrokerservice.sso.endpoint;

import com.hma.idpbrokerservice.sso.contract.adminbypassservice.BYPASSIN;
import com.hma.idpbrokerservice.sso.contract.adminbypassservice.BYPASSOUT;
import com.hma.idpbrokerservice.sso.service.AdminBypassService;
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
public class AdminBypassEndpoint {

    private static final String NS = "http://hyundaidealer.com/AdminBypassService/";
    private final AdminBypassService service;

    @PayloadRoot(namespace = NS, localPart = "AdminBypass")
    @ResponsePayload
    public Source bypass(@RequestPayload Source request) throws Exception {
        StringResult sr = new StringResult();
        TransformerFactory.newInstance().newTransformer().transform(request, sr);
        Document doc = XmlPayloadUtil.parse(sr.toString());
        Element root = doc.getDocumentElement();

        BYPASSIN in = new BYPASSIN();
        in.setAction(XmlPayloadUtil.text(root, "Action"));
        in.setAdminKey(XmlPayloadUtil.text(root, "AdminKey"));
        in.setAdminMfa(XmlPayloadUtil.text(root, "AdminMfa"));
        in.setBypassID(XmlPayloadUtil.text(root, "BypassID"));
        in.setUserID(XmlPayloadUtil.text(root, "UserID"));
        in.setTargetSystem(XmlPayloadUtil.text(root, "TargetSystem"));
        String d = XmlPayloadUtil.text(root, "DurationMinutes");
        in.setDurationMinutes(d == null || d.isBlank() ? null : Integer.parseInt(d));
        in.setJustification(XmlPayloadUtil.text(root, "Justification"));

        BYPASSOUT out = service.execute(in);

        String e = "<ERETURN>"
                + XmlPayloadUtil.tag("TYPE",    out.getERETURN() == null ? "E" : out.getERETURN().getTYPE())
                + XmlPayloadUtil.tag("MESSAGE", out.getERETURN() == null ? "" : out.getERETURN().getMESSAGE())
                + "</ERETURN>";

        String xml = "<AdminBypassResponse xmlns=\"" + NS + "\">"
                + XmlPayloadUtil.tag("BypassID",     out.getBypassID())
                + XmlPayloadUtil.tag("UserID",       out.getUserID())
                + XmlPayloadUtil.tag("TargetSystem", out.getTargetSystem())
                + XmlPayloadUtil.tag("ExpiresAt",    out.getExpiresAt())
                + XmlPayloadUtil.tag("Cancelled",    out.getCancelled() == null ? "" : String.valueOf(out.getCancelled()))
                + e
                + "</AdminBypassResponse>";
        return new StringSource(xml);
    }
}
