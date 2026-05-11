package com.hma.idpbrokerservice.sso.repository;

import com.hma.idpbrokerservice.sso.entity.OAuthState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthStateRepository extends JpaRepository<OAuthState, String> {
}
