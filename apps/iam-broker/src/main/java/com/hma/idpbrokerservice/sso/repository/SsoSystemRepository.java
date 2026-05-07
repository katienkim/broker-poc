package com.hma.idpbrokerservice.sso.repository;

import com.hma.idpbrokerservice.sso.entity.SsoSystem;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SsoSystemRepository extends JpaRepository<SsoSystem, String> {
    // Spring Data resolves findById(String) from JpaRepository — no custom queries needed for the POC.
}
