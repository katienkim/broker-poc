package com.hma.idpbrokerservice.sso.contract;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * ERETURN block: shared status-code wrapper across all SOAP services.
 * Matches the client convention (TYPE = "S"|"E", MESSAGE = code constant).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Ereturn {
    private String TYPE;
    private String MESSAGE;
}
