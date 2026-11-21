package com.lukas.security_dashboard.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {
    @GetMapping("/")
    public String healthCheck() {
        return "Security Dashboard Running";
    }
}
