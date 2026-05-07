package com.hma.idpbrokerservice.sso.token;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.domain.IssuedToken;
import com.hma.idpbrokerservice.sso.domain.UserContext;
import lombok.RequiredArgsConstructor;
import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import jakarta.annotation.PostConstruct;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.UUID;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

/**
 * SAML 2.0 Response with an enveloped XML-DSig (RSA-SHA256). Same structure
 * as the Node POC's generateSaml() but **signed**. Apache Santuario does the
 * canonicalisation + digest + sign. The Issuer KeyInfo embeds the RSA public
 * key so the vendor can verify without out-of-band cert exchange.
 */
@Component
@RequiredArgsConstructor
public class SamlTokenGenerator {

    private final SsoProperties properties;
    private final SamlSigningKeyProvider keyProvider;

    @PostConstruct void initSantuario() { Init.init(); }

    public IssuedToken generate(UserContext user, String targetUrl) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(properties.getToken().getSaml().getTtlSeconds());
        String nowIso = DateTimeFormatter.ISO_INSTANT.format(now);
        String expIso = DateTimeFormatter.ISO_INSTANT.format(exp);
        String responseId  = "_" + UUID.randomUUID();
        String assertionId = "_" + UUID.randomUUID();
        String jti = UUID.randomUUID().toString();

        String xml = """
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s">
              <saml:Issuer>http://broker.sso.test</saml:Issuer>
              <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
              <saml:Assertion ID="%s" Version="2.0" IssueInstant="%s">
                <saml:Issuer>http://broker.sso.test</saml:Issuer>
                <saml:Subject>
                  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">%s</saml:NameID>
                  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
                  </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
                  <saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
                </saml:Conditions>
                <saml:AttributeStatement>
                  <saml:Attribute Name="jti"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  <saml:Attribute Name="role"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  <saml:Attribute Name="brand"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  <saml:Attribute Name="dealer_code"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  <saml:Attribute Name="first_name"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  <saml:Attribute Name="last_name"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  <saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  <saml:Attribute Name="company"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  <saml:Attribute Name="zone"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  <saml:Attribute Name="department"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                </saml:AttributeStatement>
              </saml:Assertion>
            </samlp:Response>
            """.formatted(
                responseId, nowIso, targetUrl,
                assertionId, nowIso,
                user.getUid(), expIso, targetUrl,
                nowIso, expIso, targetUrl,
                jti, nullToEmpty(user.getRole()), nullToEmpty(user.getBrand()), nullToEmpty(user.getDealerCode()),
                nullToEmpty(user.getFirstName()), nullToEmpty(user.getLastName()), nullToEmpty(user.getEmail()),
                nullToEmpty(user.getCorporateName()), nullToEmpty(user.getZone()), nullToEmpty(user.getDepartment()));

        String signed = signRsaSha256(xml.strip(), responseId);
        String b64 = Base64.getEncoder().encodeToString(signed.getBytes(StandardCharsets.UTF_8));

        return IssuedToken.builder()
                .token(b64)
                .format("saml")
                .jti(jti)
                .issuedAt(now)
                .expiresAt(exp)
                .build();
    }

    private String signRsaSha256(String xml, String responseId) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            Element root = doc.getDocumentElement();

            // Register the ID attribute so the XML signature resolver can find it
            root.setIdAttributeNS(null, "ID", true);

            XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
            // Insert <ds:Signature> right after <Issuer> (standard SAML location).
            NodeList issuers = root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer");
            if (issuers.getLength() > 0 && issuers.item(0).getNextSibling() != null) {
                root.insertBefore(sig.getElement(), issuers.item(0).getNextSibling());
            } else {
                root.appendChild(sig.getElement());
            }

            Transforms transforms = new Transforms(doc);
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            sig.addDocument("#" + responseId, transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

            PublicKey pub = keyProvider.getKeyPair().getPublic();
            sig.addKeyInfo(pub);

            sig.sign(keyProvider.getKeyPair().getPrivate());
            return serialize(doc);
        } catch (Exception e) {
            throw new IllegalStateException("SAML signing failed", e);
        }
    }

    private static String serialize(Document doc) throws Exception {
        Transformer tr = TransformerFactory.newInstance().newTransformer();
        tr.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter sw = new StringWriter();
        tr.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }

    private static String nullToEmpty(String s) { return s == null ? "" : s; }
}
