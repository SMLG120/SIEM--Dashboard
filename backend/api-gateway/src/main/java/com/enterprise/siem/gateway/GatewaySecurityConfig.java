package com.enterprise.siem.gateway;

import com.enterprise.siem.common.security.KeycloakRealmRoleConverter;
import com.enterprise.siem.common.security.SiemRoles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class GatewaySecurityConfig {
    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/actuator/health", "/actuator/info").permitAll()
                        .pathMatchers("/api/users/**").hasRole(SiemRoles.ADMIN)
                        .pathMatchers(HttpMethod.GET, "/api/events/**").hasAnyRole(
                                SiemRoles.ADMIN,
                                SiemRoles.SOC_MANAGER,
                                SiemRoles.SECURITY_ANALYST
                        )
                        .pathMatchers("/api/events/**").hasAnyRole(
                                SiemRoles.ADMIN,
                                SiemRoles.SOC_MANAGER,
                                SiemRoles.SECURITY_ANALYST
                        )
                        .pathMatchers(HttpMethod.GET, "/api/alerts/**").hasAnyRole(
                                SiemRoles.ADMIN,
                                SiemRoles.SOC_MANAGER,
                                SiemRoles.SECURITY_ANALYST,
                                SiemRoles.VIEWER
                        )
                        .pathMatchers("/api/alerts/**").hasAnyRole(
                                SiemRoles.ADMIN,
                                SiemRoles.SOC_MANAGER,
                                SiemRoles.SECURITY_ANALYST
                        )
                        .pathMatchers(HttpMethod.GET, "/api/incidents/**").hasAnyRole(
                                SiemRoles.ADMIN,
                                SiemRoles.SOC_MANAGER,
                                SiemRoles.SECURITY_ANALYST
                        )
                        .pathMatchers("/api/incidents/**").hasAnyRole(
                                SiemRoles.ADMIN,
                                SiemRoles.SOC_MANAGER,
                                SiemRoles.SECURITY_ANALYST
                        )
                        .pathMatchers(HttpMethod.GET, "/api/rules/**").hasAnyRole(
                                SiemRoles.ADMIN,
                                SiemRoles.SOC_MANAGER,
                                SiemRoles.SECURITY_ANALYST
                        )
                        .pathMatchers("/api/rules/**").hasAnyRole(SiemRoles.ADMIN, SiemRoles.SOC_MANAGER)
                        .pathMatchers("/api/threat-intel/**").hasAnyRole(SiemRoles.ADMIN, SiemRoles.SOC_MANAGER)
                        .pathMatchers("/api/audit/**").hasAnyRole(SiemRoles.ADMIN, SiemRoles.SOC_MANAGER)
                        .pathMatchers("/api/auth/**").authenticated()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .build();
    }

    private ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }
}

