package com.hma.idpbrokerservice.sso.token;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * IdP-role RSA keypair — used by {@link SamlTokenGenerator} to sign outbound
 * vendor SAML responses. Loads from a PKCS12 keystore if configured and
 * present; otherwise generates an ephemeral keypair at startup (legacy POC
 * behavior — fine for vendor-side which doesn't pin our cert).
 */
@Component
@Getter
@Slf4j
public class SamlSigningKeyProvider {

    private final KeyPair keyPair;
    private final X509Certificate certificate;

    public SamlSigningKeyProvider(
            @Value("${SAML_IDP_KEYSTORE:}") String keystorePath,
            @Value("${SAML_IDP_KEYSTORE_PASSWORD:changeit}") String keystorePassword,
            @Value("${SAML_IDP_KEY_ALIAS:broker-idp}") String keyAlias) {

        KeyStoreLoader.Result loaded = KeyStoreLoader.load(keystorePath, keystorePassword, keyAlias);
        if (loaded != null) {
            this.keyPair = loaded.keyPair;
            this.certificate = loaded.certificate;
            log.info("[SamlSigningKeyProvider] loaded IdP keypair from keystore: {}", keystorePath);
        } else {
            log.warn("[SamlSigningKeyProvider] no keystore configured or file missing — "
                    + "generating ephemeral IdP keypair (will not survive restart)");
            this.keyPair = generateEphemeral();
            this.certificate = null;
        }
    }

    private static KeyPair generateEphemeral() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate SAML signing key", e);
        }
    }

    /** Shared loader used by both IdP-role and SP-role key providers. */
    static final class KeyStoreLoader {
        record Result(KeyPair keyPair, X509Certificate certificate) {}

        static Result load(String path, String password, String alias) {
            if (path == null || path.isBlank()) return null;
            Path p = Path.of(path);
            if (!Files.isReadable(p)) return null;
            try (InputStream in = Files.newInputStream(p)) {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(in, password.toCharArray());
                PrivateKey priv = (PrivateKey) ks.getKey(alias, password.toCharArray());
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                if (priv == null || cert == null) {
                    throw new IllegalStateException(
                            "keystore " + path + " has no entry for alias " + alias);
                }
                PublicKey pub = cert.getPublicKey();
                return new Result(new KeyPair(pub, priv), cert);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to load keystore " + path, e);
            }
        }
    }
}
