package com.enterprise.siem.detection;

import com.enterprise.siem.common.security.KeycloakRealmRoleConverter;
import com.enterprise.siem.common.security.SiemRoles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class DetectionSecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health/**", "/actuator/info", "/actuator/prometheus").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/detection/**", "/api/rules/**").hasAnyRole(
                                SiemRoles.ADMIN,
                                SiemRoles.SOC_MANAGER,
                                SiemRoles.SECURITY_ANALYST
                        )
                        .requestMatchers("/api/rules/**").hasAnyRole(SiemRoles.ADMIN, SiemRoles.SOC_MANAGER)
                        .requestMatchers("/api/detection/**").hasAnyRole(SiemRoles.ADMIN, SiemRoles.SOC_MANAGER)
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .build();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return converter;
    }
}

