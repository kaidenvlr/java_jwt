package org.kaiden.jwtauthentication.web.controllers;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HelloController {
    @GetMapping("/hello")
    public String hello(HttpServletRequest request) {
        String sub = (String) request.getAttribute("auth.sub");
        return "Hello, " + sub + "!";
    }
}
