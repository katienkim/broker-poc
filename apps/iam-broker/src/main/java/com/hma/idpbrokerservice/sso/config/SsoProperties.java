package com.hma.idpbrokerservice.sso.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Type-safe binding for `sso.*` keys in application-sso.yaml.
 * Mirrors the nested-static-class pattern used by the client backend's SsoProperties.
 */
@Data
@ConfigurationProperties(prefix = "sso")
public class SsoProperties {

    private boolean enabled = true;
    private Token token = new Token();
    private External external = new External();
    private Admin admin = new Admin();
    private RateLimit rateLimit = new RateLimit();
    private Bypass bypass = new Bypass();
    private boolean targetSystemsSeedOnEmpty = true;
    private Oidc oidc = new Oidc();
    private SamlSp samlSp = new SamlSp();
    private SamlIdp samlIdp = new SamlIdp();
    private MockPid mockPid = new MockPid();

    @Data
    public static class Token {
        private String defaultPrefix;
        private String timestampFormat;
        private Igtk igtk = new Igtk();
        private Saml saml = new Saml();
        private Aes256 aes256 = new Aes256();
        private Rc4 rc4 = new Rc4();
        private WpcOtp wpcOtp = new WpcOtp();
    }

    @Data public static class Igtk    { private int ttlSeconds; }
    @Data public static class Saml    { private int ttlSeconds; }
    @Data public static class Aes256  { private int ttlSeconds; private String sharedKey; }
    @Data public static class Rc4     { private int ttlSeconds; private String sharedKey; }
    @Data public static class WpcOtp  { private int ttlSeconds; }

    @Data
    public static class External {
        private String pidValidateUrl;
        private String dealersAttrUrl;
        private String dashboardUrl;
        private String brokerPublicUrl;
    }

    @Data
    public static class Admin {
        private String apiKey;
        private boolean requireMfaHeader;
    }

    @Data
    public static class RateLimit {
        private Otp otp = new Otp();

        @Data
        public static class Otp {
            private int perIpLimit;
            private long perIpWindowMs;
            private int lockoutFailures;
            private long lockoutWindowMs;
            private long lockoutDurationMs;
        }
    }

    @Data
    public static class Bypass {
        private int maxDurationMinutes;
    }

    /** OIDC RP config — broker authenticates users at an upstream OIDC IdP (e.g. PID). */
    @Data
    public static class Oidc {
        private Pid pid = new Pid();

        @Data
        public static class Pid {
            private boolean enabled;
            private String clientId;
            private String clientSecret;
            private String issuer;
            private String authorizeEndpoint;
            private String tokenEndpoint;
            private String jwksUri;
            private String redirectUri;
            private String scopes = "openid profile email";
            private int stateCodeExpiryMinutes = 5;
        }
    }

    /** SP-role config — broker receives SAML assertions from an upstream IdP. */
    @Data
    public static class SamlSp {
        private boolean enabled = true;
        private String entityId;
        private String keystorePath;
        private String keystorePassword;
        private String keyAlias;
        private String acsUrl;
        private String registrationId = "pid";
        private int metadataValidityDays = 365;
        private boolean wantAssertionsSigned = true;
    }

    /** Upstream IdP config — the broker validates assertions signed by this IdP. */
    @Data
    public static class SamlIdp {
        private String entityId;
        private String metadataPath;
    }

    /** Mock-PID launch-token signing — see Phase 4 in plan. */
    @Data
    public static class MockPid {
        private boolean requireSignature;
        private String sharedSecret;
    }
}
