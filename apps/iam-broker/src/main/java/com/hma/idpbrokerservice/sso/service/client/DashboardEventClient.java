package com.hma.idpbrokerservice.sso.service.client;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

/**
 * Fire-and-forget POST to flow-dashboard /api/event. Mirrors the Node
 * lib/dashboard.js — errors are swallowed, dashboard is non-critical.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DashboardEventClient {

    private final WebClient.Builder webClientBuilder;
    private final SsoProperties properties;

    public void emit(Map<String, Object> event) {
        try {
            webClientBuilder.build().post()
                    .uri(properties.getExternal().getDashboardUrl() + "/api/event")
                    .bodyValue(event)
                    .retrieve()
                    .toBodilessEntity()
                    .subscribe(r -> {}, err -> log.debug("[Dashboard] emit failed: {}", err.getMessage()));
        } catch (Exception ignored) {}
    }
}
