package org.kaiden.jwtauthentication.web.dto;

import org.kaiden.jwtauthentication.models.Role;

import java.util.Set;

public record UserResponse(Long id, String username, Set<Role> roles) {
}
