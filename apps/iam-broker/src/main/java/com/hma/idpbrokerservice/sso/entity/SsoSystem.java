package com.hma.idpbrokerservice.sso.entity;

import jakarta.persistence.*;
import lombok.Data;

/**
 * Vendor catalog row. Mirrors poc/apps/iam-broker/src/lib/target-systems.js
 * one-for-one. Brought into the DB so the broker is stateless on restart and
 * the catalog can be edited without a code change (matches the client
 * IA_TB_SSO_SYS_MNGMT_M model).
 */
@Data
@Entity
@Table(name = "ia_tb_sso_sys_mngmt_m")
public class SsoSystem {

    @Id
    @Column(name = "source_sys_id", length = 64)
    private String sourceSysId;     // e.g. "vendor-igtk"

    @Column(name = "source_sys_name", length = 128)
    private String sourceSysName;   // e.g. "IGTK Vendor App"

    @Column(name = "source_sys_type", length = 16)
    private String sourceSysType;   // TokenFormat code: igtk / saml / aes256 / rc4 / wpc-otp

    @Column(name = "direct_reurl_d", length = 512)
    private String directReurlD;    // desktop redirect URL — what the broker auto-submits to

    @Column(name = "direct_reurl_m", length = 512)
    private String directReurlM;    // mobile redirect URL (unused in POC; populated for fidelity)

    @Column(name = "is_source_sys_active")
    private Integer isSourceSysActive;  // 1 = active, 0 = inactive

    @Column(name = "requires_dealer_code")
    private Integer requiresDealerCode; // informational; user-level check is delegated per Yoonmi/Ahn Dae Hyun

    @Column(name = "deprecated")
    private Integer deprecated;     // 1 = deprecated (RC4 today)

    @Column(name = "allowed_roles_csv", length = 256)
    private String allowedRolesCsv;  // comma-separated; informational only at the broker

    @Column(name = "allowed_brands_csv", length = 64)
    private String allowedBrandsCsv;
}
