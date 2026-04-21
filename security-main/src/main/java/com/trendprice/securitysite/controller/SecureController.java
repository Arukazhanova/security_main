package com.trendprice.securitysite.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecureController {

    @GetMapping("/api/secure")
    public String secure(Authentication auth) {
        return "You are authorized! Hello, " + auth.getName();
    }
}