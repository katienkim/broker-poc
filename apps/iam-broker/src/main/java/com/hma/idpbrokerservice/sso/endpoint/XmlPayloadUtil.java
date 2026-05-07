package com.hma.idpbrokerservice.sso.endpoint;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

/**
 * Tiny XML helper used by all SOAP endpoints. Mirrors client's XmlPayloadUtil.
 * The client also hand-builds response XML as strings (no JAXB marshalling) to
 * preserve the exact namespace-prefix layout legacy SoapUI templates produce.
 */
public final class XmlPayloadUtil {

    private XmlPayloadUtil() {}

    public static Document parse(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        return f.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    /** Returns the text of the first child element matching the local name, or "" if absent. */
    public static String text(Element root, String localName) {
        NodeList nl = root.getElementsByTagNameNS("*", localName);
        if (nl.getLength() == 0) return "";
        return nl.item(0).getTextContent();
    }

    public static String xmlEscape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    /** Wraps a value in a no-prefix element. Null/empty → empty element. */
    public static String tag(String name, String value) {
        return "<" + name + ">" + xmlEscape(value) + "</" + name + ">";
    }
}
