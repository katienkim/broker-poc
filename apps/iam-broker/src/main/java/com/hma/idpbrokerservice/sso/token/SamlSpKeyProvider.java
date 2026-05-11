package com.hma.idpbrokerservice.sso.token;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

/**
 * SP-role RSA keypair — used to sign outbound AuthnRequests, decrypt encrypted
 * assertions, and as the public key advertised in the SP metadata served at
 * /sso/saml/metadata. Separate from {@link SamlSigningKeyProvider} (IdP-role)
 * so the cert published to PID stays stable across changes to the vendor-side
 * signing key.
 *
 * Loads from {@code sso.saml-sp.keystore-path}; falls back to an ephemeral
 * keypair if the file is missing (POC bootstrapping — generate the keystore
 * via keytool when ready, see chat history for command).
 */
@Component
@Getter
@Slf4j
public class SamlSpKeyProvider {

    private final KeyPair keyPair;
    private final X509Certificate certificate;
    private final boolean ephemeral;

    public SamlSpKeyProvider(SsoProperties properties) {
        SsoProperties.SamlSp cfg = properties.getSamlSp();
        SamlSigningKeyProvider.KeyStoreLoader.Result loaded =
                SamlSigningKeyProvider.KeyStoreLoader.load(
                        cfg.getKeystorePath(), cfg.getKeystorePassword(), cfg.getKeyAlias());
        if (loaded != null) {
            this.keyPair = loaded.keyPair();
            this.certificate = loaded.certificate();
            this.ephemeral = false;
            log.info("[SamlSpKeyProvider] loaded SP keypair from keystore: {}",
                    cfg.getKeystorePath());
        } else {
            log.warn("[SamlSpKeyProvider] keystore {} missing — generating ephemeral SP keypair. "
                    + "Cert advertised in /sso/saml/metadata will change on every restart. "
                    + "Run keytool to mint a stable keystore (see docs).",
                    cfg.getKeystorePath());
            this.keyPair = generateEphemeral();
            this.certificate = null;
            this.ephemeral = true;
        }
    }

    private static KeyPair generateEphemeral() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate SP signing key", e);
        }
    }
}
