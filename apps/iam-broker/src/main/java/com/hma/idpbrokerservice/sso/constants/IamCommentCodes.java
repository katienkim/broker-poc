package com.hma.idpbrokerservice.sso.constants;

/**
 * Comment codes returned in SOAP ERETURN.TYPE / ERETURN.MESSAGE.
 * Mirrors the legacy EJB convention used by the client backend so vendors that
 * already integrate with the legacy broker get identical response shapes.
 */
public final class IamCommentCodes {

    // ERETURN.TYPE values
    public static final String TYPE_SUCCESS = "S";
    public static final String TYPE_ERROR   = "E";

    // ERETURN.MESSAGE values — keep stable; vendor-side parsers may match exactly
    public static final String MSG_SUCCESS               = "SUCCESS";
    public static final String MSG_TARGET_NOT_FOUND      = "TARGET_NOT_FOUND";
    public static final String MSG_TARGET_INACTIVE       = "TARGET_INACTIVE";
    public static final String MSG_LAUNCH_TOKEN_INVALID  = "LAUNCH_TOKEN_INVALID";
    public static final String MSG_DEALERS_UNAVAILABLE   = "DEALERS_UNAVAILABLE";
    public static final String MSG_TOKEN_EXPIRED         = "TOKEN_EXPIRED";
    public static final String MSG_TOKEN_REVOKED         = "TOKEN_REVOKED";
    public static final String MSG_USER_REVOKED          = "USER_REVOKED";
    public static final String MSG_TOKEN_NOT_FOUND       = "TOKEN_NOT_FOUND";
    public static final String MSG_TOKEN_ALREADY_USED    = "TOKEN_ALREADY_USED";
    public static final String MSG_OTP_INVALID           = "OTP_INVALID";
    public static final String MSG_OTP_LOCKED            = "OTP_LOCKED";
    public static final String MSG_UNAUTHORIZED          = "UNAUTHORIZED";
    public static final String MSG_MFA_REQUIRED          = "MFA_REQUIRED";
    public static final String MSG_BAD_REQUEST           = "BAD_REQUEST";

    // Brand prefix flags (mirror client IamCommentCodes.HMA_FLAG / GMA_FLAG)
    public static final String HMA_FLAG = "H_";
    public static final String GMA_FLAG = "G_";

    private IamCommentCodes() {}
}
