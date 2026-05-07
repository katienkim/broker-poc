package com.hma.idpbrokerservice.sso.repository;

import com.hma.idpbrokerservice.sso.entity.SsoRevocation;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SsoRevocationRepository extends JpaRepository<SsoRevocation, String> {
}
