package com.hma.idpbrokerservice.sso.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Aggregated user view passed to token generators.
 * Matches the real legacy SSOOUT / IAMUserProfile attribute set.
 * PID provides base identity; ENA (Dealers Attribute DB) provides the rest.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserContext {
    // --- PID base claims ---
    private String uid;
    private String userType;          // "PID"

    // --- ENA enrichment (matches legacy IAMUserProfile) ---
    private String role;              // DEALER_MANAGER, DEALER_STAFF, VENDOR, CORPORATE, etc.
    private String brand;             // "H" or "GMA"
    private String dealerCode;        // e.g. "ON-1234", "H-001"
    private String firstName;
    private String lastName;
    private String email;
    private String corporateCode;     // dealer code or "00000" for corporate
    private String corporateName;     // company name
    private String jobCode;           // semicolon-separated for multiple
    private String jobTitle;          // semicolon-separated for multiple
    private String department;
    private String position;
    private String regionCode;
    private String salesDistrict;
    private String serviceDistrict;
    private String partsDistrict;
    private String dealerStateCode;
    private String dealerTypeCode;
    private String zone;
    private String district;
    private String accessLevel;       // NATL, REGN, DIST, DEAR
    private String permissionGroups;  // functional group IDs
}
