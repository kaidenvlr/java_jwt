package org.kaiden.jwtauthentication.web.controllers;

import org.kaiden.jwtauthentication.crypto.PasswordHasher;
import org.kaiden.jwtauthentication.jwt.JwtUtil;
import org.kaiden.jwtauthentication.models.Role;
import org.kaiden.jwtauthentication.models.UserEntity;
import org.kaiden.jwtauthentication.repo.UserRepository;
import org.kaiden.jwtauthentication.web.dto.AuthRequest;
import org.kaiden.jwtauthentication.web.dto.AuthResponse;
import org.kaiden.jwtauthentication.web.dto.RegisterRequest;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final UserRepository users;

    public AuthController(UserRepository users) {
        this.users = users;
    }

    @PostMapping("/register")
    @Transactional
    public AuthResponse register(@RequestBody RegisterRequest req) {
        if (users.existsByUsername(req.username())) {
            throw new IllegalArgumentException("Username is already in use");
        }

        var u = new UserEntity();
        u.setUsername(req.username());
        u.setPasswordHash(PasswordHasher.hash(req.password()));
        u.setRoles(Set.of(Role.USER));
        users.save(u);

        String token = JwtUtil.generate(u.getUsername(), 3600, Map.of("uid", u.getId()));
        return new AuthResponse(token);
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody AuthRequest req) {
        var u = users.findByUsername(req.username())
                .orElseThrow(() -> new IllegalArgumentException("Invalid username or password"));

        if (!PasswordHasher.verify(req.password(), u.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid username or password");
        }

        String token = JwtUtil.generate(u.getUsername(), 3600, Map.of("uid", u.getId()));
        return new AuthResponse(token);
    }
}
