package com.hma.idpbrokerservice.sso.service.client;

import com.hma.idpbrokerservice.sso.config.SsoProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.Map;

/**
 * Server-to-server call to mock-pid /auth/validate-launch-token. Defense-in-depth:
 * PID already marks the jti consumed at step 7 (browser hop), this catches forged
 * tokens that never went through PID at all.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PidLaunchTokenClient {

    private final WebClient.Builder webClientBuilder;
    private final SsoProperties properties;

    @SuppressWarnings("unchecked")
    public Map<String, Object> validate(String jti) {
        try {
            return webClientBuilder.build().post()
                    .uri(properties.getExternal().getPidValidateUrl())
                    .bodyValue(Map.of("jti", jti))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();
        } catch (Exception e) {
            log.warn("[PidValidate] failed: {}", e.getMessage());
            Map<String, Object> err = new HashMap<>();
            err.put("valid", false);
            err.put("error", "PID_UNREACHABLE");
            return err;
        }
    }
}
