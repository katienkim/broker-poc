package com.hma.idpbrokerservice.sso.endpoint;

import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PARAMIN;
import com.hma.idpbrokerservice.sso.contract.publishtokenservice.PUBLISHOUT;
import com.hma.idpbrokerservice.sso.service.PublishTokenService;
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

/** SOAP entry to PublishTokenService. Mirrors client's PublishTokenEndpoint. */
@Endpoint
@RequiredArgsConstructor
public class PublishTokenEndpoint {

    private static final String NS = "http://hyundaidealer.com/PublishTokenService/";
    private final PublishTokenService service;

    @PayloadRoot(namespace = NS, localPart = "PublishToken")
    @ResponsePayload
    public Source createToken(@RequestPayload Source request) throws Exception {
        StringResult sr = new StringResult();
        TransformerFactory.newInstance().newTransformer().transform(request, sr);
        Document doc = XmlPayloadUtil.parse(sr.toString());
        Element root = doc.getDocumentElement();

        PARAMIN in = new PARAMIN();
        in.setLaunchToken(XmlPayloadUtil.text(root, "LaunchToken"));
        in.setSourceSYSID(XmlPayloadUtil.text(root, "SourceSYS_ID"));
        in.setTargetSYSID(XmlPayloadUtil.text(root, "TargetSYS_ID"));
        in.setUserID(XmlPayloadUtil.text(root, "UserID"));
        in.setCompanyCode(XmlPayloadUtil.text(root, "CompanyCode"));
        in.setFlowID(XmlPayloadUtil.text(root, "FlowID"));

        PUBLISHOUT out = service.createToken(in);

        String e = out.getERETURN() == null
                ? "<ERETURN><TYPE>E</TYPE><MESSAGE>UNKNOWN</MESSAGE></ERETURN>"
                : "<ERETURN>"
                  + XmlPayloadUtil.tag("TYPE", out.getERETURN().getTYPE())
                  + XmlPayloadUtil.tag("MESSAGE", out.getERETURN().getMESSAGE())
                  + "</ERETURN>";

        String xml = "<PublishTokenResponse xmlns=\"" + NS + "\">"
                + XmlPayloadUtil.tag("htxtToken",    out.getHtxtToken())
                + XmlPayloadUtil.tag("UserID",       out.getUserID())
                + XmlPayloadUtil.tag("SourceSYS_ID", out.getSourceSYSID())
                + XmlPayloadUtil.tag("TargetSYS_ID", out.getTargetSYSID())
                + e
                + XmlPayloadUtil.tag("URL_D",        out.getURLD())
                + XmlPayloadUtil.tag("URL_M",        out.getURLM())
                + XmlPayloadUtil.tag("Format",       out.getFormat())
                + XmlPayloadUtil.tag("JTI",          out.getJTI())
                + "</PublishTokenResponse>";
        return new StringSource(xml);
    }
}
