package org.kaiden.jwtauthentication.web.controllers;

import jakarta.servlet.http.HttpServletRequest;
import org.kaiden.jwtauthentication.repo.UserRepository;
import org.kaiden.jwtauthentication.web.dto.UserResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/me")
    public UserResponse me(HttpServletRequest request) {
        String username = (String) request.getAttribute("auth.sub");
        var u = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return new UserResponse(u.getId(), u.getUsername(), u.getRoles());
    }
}
