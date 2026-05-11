package com.hma.idpbrokerservice.sso.repository;

import com.hma.idpbrokerservice.sso.entity.InboundSamlAssertionSeen;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InboundSamlAssertionSeenRepository
        extends JpaRepository<InboundSamlAssertionSeen, String> {
}
