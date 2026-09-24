package com.enterprise.siem.common.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

public final class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private static final String REALM_ACCESS = "realm_access";
    private static final String ROLES = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Object realmAccess = jwt.getClaim(REALM_ACCESS);
        if (!(realmAccess instanceof Map<?, ?> claims)) {
            return List.of();
        }

        Object roles = claims.get(ROLES);
        if (!(roles instanceof Collection<?> roleValues)) {
            return List.of();
        }

        return roleValues.stream()
                .filter(Objects::nonNull)
                .flatMap(KeycloakRealmRoleConverter::authority)
                .toList();
    }

    private static Stream<GrantedAuthority> authority(Object role) {
        String value = role.toString().trim();
        if (value.isEmpty()) {
            return Stream.empty();
        }
        return Stream.of(new SimpleGrantedAuthority(ROLE_PREFIX + value));
    }
}

