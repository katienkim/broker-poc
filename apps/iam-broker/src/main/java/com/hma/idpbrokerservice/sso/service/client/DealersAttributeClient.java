package com.hma.idpbrokerservice.sso.service.client;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.Map;

/**
 * GET {dealersAttrUrl}/users/{uid}. Returns the role/brand/dealer_code/etc.
 * for the user. The DB is owned by Dealers — broker just enriches with this.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DealersAttributeClient {

    private final WebClient.Builder webClientBuilder;
    private final SsoProperties properties;

    @SuppressWarnings("unchecked")
    public Map<String, Object> fetchAttributes(String uid) {
        try {
            return webClientBuilder.build().get()
                    .uri(properties.getExternal().getDealersAttrUrl() + "/users/{uid}", uid)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();
        } catch (Exception e) {
            log.warn("[DealersAttr] {} -> {}", uid, e.getMessage());
            return new HashMap<>();
        }
    }
}
