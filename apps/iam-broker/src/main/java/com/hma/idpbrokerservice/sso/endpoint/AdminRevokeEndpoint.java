package com.hma.idpbrokerservice.sso.endpoint;

import com.hma.idpbrokerservice.sso.contract.adminrevokeservice.REVOKEIN;
import com.hma.idpbrokerservice.sso.contract.adminrevokeservice.REVOKEOUT;
import com.hma.idpbrokerservice.sso.service.AdminRevokeService;
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
public class AdminRevokeEndpoint {

    private static final String NS = "http://hyundaidealer.com/AdminRevokeService/";
    private final AdminRevokeService service;

    @PayloadRoot(namespace = NS, localPart = "AdminRevoke")
    @ResponsePayload
    public Source revoke(@RequestPayload Source request) throws Exception {
        StringResult sr = new StringResult();
        TransformerFactory.newInstance().newTransformer().transform(request, sr);
        Document doc = XmlPayloadUtil.parse(sr.toString());
        Element root = doc.getDocumentElement();

        REVOKEIN in = new REVOKEIN();
        in.setAdminKey(XmlPayloadUtil.text(root, "AdminKey"));
        in.setTokenID(XmlPayloadUtil.text(root, "TokenID"));
        in.setUserID(XmlPayloadUtil.text(root, "UserID"));
        in.setReason(XmlPayloadUtil.text(root, "Reason"));

        REVOKEOUT out = service.revoke(in);

        String e = "<ERETURN>"
                + XmlPayloadUtil.tag("TYPE",    out.getERETURN() == null ? "E" : out.getERETURN().getTYPE())
                + XmlPayloadUtil.tag("MESSAGE", out.getERETURN() == null ? "" : out.getERETURN().getMESSAGE())
                + "</ERETURN>";

        String xml = "<AdminRevokeResponse xmlns=\"" + NS + "\">"
                + XmlPayloadUtil.tag("Revoked", String.valueOf(out.isRevoked()))
                + XmlPayloadUtil.tag("Type",    out.getType())
                + XmlPayloadUtil.tag("ID",      out.getID())
                + e
                + "</AdminRevokeResponse>";
        return new StringSource(xml);
    }
}
