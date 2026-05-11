package com.hma.idpbrokerservice.sso.config;

import com.hma.idpbrokerservice.sso.service.InboundSamlReplayGuard;
import com.hma.idpbrokerservice.sso.service.SamlSuccessHandler;
import com.hma.idpbrokerservice.sso.token.SamlSpKeyProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Conditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

/**
 * Wires Spring Security SAML2 to validate inbound assertions from PID and
 * delegates the success path to {@link SamlSuccessHandler}. Two filter chains:
 * (1) SAML2 chain on {@code /sso/saml/**} + {@code /saml2/**}, (2) permit-all
 * everywhere else so the broker's existing endpoints (SOAP /ws, /health,
 * /sso/receive, REST shims) keep working unauthenticated.
 *
 * Disable via {@code SSO_SAML_SP_ENABLED=false} to skip wiring entirely
 * (useful before the SP keystore has been generated via keytool).
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class SamlSecurityConfig {

    private final SsoProperties props;

    /**
     * Loads the SP/IdP federation. Only registered when SAML SP is enabled
     * AND the SP keystore has been loaded — otherwise the broker boots fine
     * and SAML routes just 404.
     */
    @Bean
    @ConditionalOnProperty(name = "sso.saml-sp.enabled", havingValue = "true", matchIfMissing = true)
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(
            SamlSpKeyProvider spKeys) {
        SsoProperties.SamlSp sp = props.getSamlSp();
        SsoProperties.SamlIdp idp = props.getSamlIdp();

        if (spKeys.getCertificate() == null) {
            throw new IllegalStateException(
                    "SAML SP enabled but no signing cert is available. "
                            + "Generate " + sp.getKeystorePath() + " via keytool, mount it into the "
                            + "container, and restart. Or set SSO_SAML_SP_ENABLED=false to skip "
                            + "SAML wiring entirely.");
        }
        Path metadataPath = Path.of(idp.getMetadataPath());
        if (!Files.isReadable(metadataPath)) {
            throw new IllegalStateException(
                    "IdP metadata not readable at " + metadataPath
                            + " — expected PID's metadata XML there.");
        }

        Saml2X509Credential signingCred = Saml2X509Credential.signing(
                spKeys.getKeyPair().getPrivate(), spKeys.getCertificate());
        Saml2X509Credential decryptionCred = Saml2X509Credential.decryption(
                spKeys.getKeyPair().getPrivate(), spKeys.getCertificate());

        RelyingPartyRegistration registration;
        try (InputStream in = Files.newInputStream(metadataPath)) {
            registration = RelyingPartyRegistrations.fromMetadata(in)
                    .registrationId(sp.getRegistrationId())
                    .entityId(sp.getEntityId())
                    .assertionConsumerServiceLocation(sp.getAcsUrl())
                    .signingX509Credentials(c -> c.add(signingCred))
                    .decryptionX509Credentials(c -> c.add(decryptionCred))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load IdP metadata from " + metadataPath, e);
        }

        log.info("[SAML SP] registered '{}' — SP entityId={}, ACS={}, IdP entityId={}",
                sp.getRegistrationId(), sp.getEntityId(), sp.getAcsUrl(),
                registration.getAssertingPartyDetails().getEntityId());

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    /**
     * SAML2 filter chain. Validates IdP-signed assertions, runs our replay
     * check, then hands off to {@link SamlSuccessHandler}.
     */
    @Bean
    @Order(1)
    @ConditionalOnProperty(name = "sso.saml-sp.enabled", havingValue = "true", matchIfMissing = true)
    public SecurityFilterChain samlFilterChain(
            HttpSecurity http,
            InboundSamlReplayGuard replayGuard,
            SamlSuccessHandler successHandler) throws Exception {

        OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
        provider.setAssertionValidator(assertionToken -> {
            // Run Spring Security's built-in checks first (signature already verified
            // upstream; this validator handles Conditions / SubjectConfirmation).
            Saml2ResponseValidatorResult builtIn =
                    OpenSaml4AuthenticationProvider.createDefaultAssertionValidator()
                            .convert(assertionToken);
            if (builtIn != null && builtIn.hasErrors()) return builtIn;

            // Custom replay check by AssertionID.
            try {
                Assertion assertion = assertionToken.getAssertion();
                String assertionId = assertion.getID();
                Conditions cond = assertion.getConditions();
                Instant notOnOrAfter = cond != null && cond.getNotOnOrAfter() != null
                        ? cond.getNotOnOrAfter()
                        : Instant.now().plusSeconds(300);
                String issuer = assertion.getIssuer() != null
                        ? assertion.getIssuer().getValue() : "unknown";
                String subject = assertion.getSubject() != null
                        && assertion.getSubject().getNameID() != null
                        ? assertion.getSubject().getNameID().getValue() : null;
                replayGuard.recordOrThrow(assertionId, issuer, subject, notOnOrAfter);
                return Saml2ResponseValidatorResult.success();
            } catch (InboundSamlReplayGuard.ReplayDetectedException e) {
                return Saml2ResponseValidatorResult.failure(
                        new Saml2Error("REPLAY_DETECTED", e.getMessage()));
            }
        });

        http
                .securityMatcher("/sso/saml/**", "/saml2/**", "/login/saml2/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/sso/saml/metadata").permitAll()
                        .anyRequest().authenticated())
                .saml2Login(saml -> saml
                        .authenticationManager(new ProviderManager(provider))
                        .loginProcessingUrl("/sso/saml/acs/{registrationId}")
                        .successHandler(successHandler)
                        .failureHandler((req, resp, ex) -> {
                            log.error("[SAML SP] authentication failure: {}", ex.getMessage());
                            resp.setStatus(401);
                            resp.setContentType("text/html");
                            resp.getWriter().write(
                                    "<!DOCTYPE html><html><body><h2>SSO Error</h2>"
                                            + "<p>SAML authentication failed: "
                                            + ex.getMessage().replace("<", "&lt;")
                                            + "</p></body></html>");
                        }));
        return http.build();
    }

    /**
     * Permit-all chain for everything outside the SAML scope. Keeps the
     * pre-existing endpoints (SOAP /ws, /health, /sso/receive, REST shims)
     * working without any auth required.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain permitAllChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}
