package com.hma.idpbrokerservice.sso.token;

import lombok.Getter;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * One RSA-2048 keypair generated at startup. Matches mock-pid's lifecycle —
 * fresh cert every restart is fine for the POC; production swaps in a vault.
 */
@Component
@Getter
public class SamlSigningKeyProvider {

    private final KeyPair keyPair;

    public SamlSigningKeyProvider() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            this.keyPair = g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate SAML signing key", e);
        }
    }
}
