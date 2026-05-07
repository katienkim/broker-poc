package com.hma.idpbrokerservice.sso.enums;

/**
 * Vendor token formats supported by the broker.
 * Code values match the strings stored in IA_TB_SSO_SYS_MNGMT_M.SOURCE_SYS_TYPE.
 * `from()` mirrors client SsoType.from() — null/unknown collapses to UNKNOWN.
 */
public enum TokenFormat {
    IGTK("igtk"),
    SAML("saml"),
    AES256("aes256"),
    RC4("rc4"),
    WPC_OTP("wpc-otp"),
    UNKNOWN("");

    private final String code;

    TokenFormat(String code) { this.code = code; }
    public String code() { return code; }

    public static TokenFormat from(String code) {
        if (code == null) return UNKNOWN;
        for (TokenFormat t : values()) {
            if (t.code.equalsIgnoreCase(code.trim())) return t;
        }
        return UNKNOWN;
    }
}
