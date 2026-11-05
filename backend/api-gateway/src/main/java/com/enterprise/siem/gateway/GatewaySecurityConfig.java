package com.enterprise.siem.gateway;

import com.enterprise.siem.common.correlation.CorrelationHeaders;
import com.enterprise.siem.common.security.KeycloakRealmRoleConverter;
import com.enterprise.siem.common.security.SiemRoles;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class GatewaySecurityConfig {
    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(Customizer.withDefaults())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/actuator/health/**", "/actuator/info", "/actuator/prometheus").permitAll()
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
                        .pathMatchers("/api/search/**").hasAnyRole(
                                SiemRoles.ADMIN,
                                SiemRoles.SOC_MANAGER,
                                SiemRoles.SECURITY_ANALYST
                        )
                        .pathMatchers("/api/audit/**").hasAnyRole(SiemRoles.ADMIN, SiemRoles.SOC_MANAGER)
                        .pathMatchers("/api/auth/**").authenticated()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .build();
    }

    /**
     * CORS lives in the security chain (not spring.cloud.gateway.globalcors) so that responses
     * rejected by Spring Security, such as 401 and 403, still carry CORS headers and the
     * browser lets the dashboard read their status.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(@Value("${siem.cors.allowed-origin}") String allowedOrigin) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(allowedOrigin));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of(CorrelationHeaders.CORRELATION_ID));
        config.setAllowCredentials(false);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }
}

