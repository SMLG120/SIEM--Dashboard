package com.enterprise.siem.common;

import com.enterprise.siem.common.security.KeycloakRealmRoleConverter;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakRealmRoleConverterTest {
    @Test
    void convertsRealmRolesToSpringAuthorities() {
        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(300),
                Map.of("alg", "none"),
                Map.of("realm_access", Map.of("roles", List.of("ADMIN", "SECURITY_ANALYST")))
        );

        assertThat(new KeycloakRealmRoleConverter().convert(jwt))
                .extracting("authority")
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_SECURITY_ANALYST");
    }

    @Test
    void returnsEmptyAuthoritiesWhenRolesAreAbsent() {
        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(300),
                Map.of("alg", "none"),
                Map.of("sub", "sam")
        );

        assertThat(new KeycloakRealmRoleConverter().convert(jwt)).isEmpty();
    }
}

