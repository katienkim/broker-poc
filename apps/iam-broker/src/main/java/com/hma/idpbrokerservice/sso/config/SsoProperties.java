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
}
