package com.hma.idpbrokerservice.presentation.controller;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import com.hma.idpbrokerservice.sso.token.SamlSpKeyProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

/**
 * Serves the SP metadata XML at <code>GET /sso/saml/metadata</code>. Replaces
 * the hand-edited /Users/katiekim/Projects/IdP/spglobalnew_allowcu-metadata.xml.
 *
 * Hand-rolled XML for Phase 1 — Spring Security SAML2's
 * {@code OpenSamlMetadataResolver} is the long-term path but pulling it in
 * here would also auto-enable a SAML2 filter chain we don't want until Phase 2.
 */
@RestController
@RequiredArgsConstructor
public class SamlMetadataController {

    private final SsoProperties properties;
    private final SamlSpKeyProvider spKeys;

    @GetMapping(value = "/sso/saml/metadata", produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> metadata() {
        if (spKeys.getCertificate() == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .contentType(MediaType.TEXT_PLAIN)
                    .body("SP keystore not configured. Generate "
                            + properties.getSamlSp().getKeystorePath()
                            + " via keytool, then restart. See chat history for the command.");
        }

        SsoProperties.SamlSp cfg = properties.getSamlSp();
        String certB64;
        try {
            certB64 = Base64.getEncoder().encodeToString(spKeys.getCertificate().getEncoded());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to encode SP cert: " + e.getMessage());
        }

        String validUntil = Instant.now()
                .plus(cfg.getMetadataValidityDays(), ChronoUnit.DAYS)
                .toString();

        String xml = """
                <?xml version="1.0" encoding="UTF-8"?>
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                     entityID="%s"
                                     validUntil="%s">
                  <md:SPSSODescriptor AuthnRequestsSigned="true"
                                      WantAssertionsSigned="%s"
                                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:KeyDescriptor use="signing">
                      <ds:KeyInfo>
                        <ds:X509Data>
                          <ds:X509Certificate>%s</ds:X509Certificate>
                        </ds:X509Data>
                      </ds:KeyInfo>
                    </md:KeyDescriptor>
                    <md:KeyDescriptor use="encryption">
                      <ds:KeyInfo>
                        <ds:X509Data>
                          <ds:X509Certificate>%s</ds:X509Certificate>
                        </ds:X509Data>
                      </ds:KeyInfo>
                    </md:KeyDescriptor>
                    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
                    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                    <md:AssertionConsumerService index="0" isDefault="true"
                        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="%s"/>
                  </md:SPSSODescriptor>
                </md:EntityDescriptor>
                """.formatted(
                cfg.getEntityId(),
                validUntil,
                String.valueOf(cfg.isWantAssertionsSigned()),
                certB64,
                certB64,
                cfg.getAcsUrl());

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_XML)
                .body(xml);
    }
}
