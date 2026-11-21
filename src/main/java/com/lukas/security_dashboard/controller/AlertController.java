package com.lukas.security_dashboard.controller;

import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.service.AlertService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {
    private final AlertService service;

    public AlertController(AlertService service) {
        this.service = service;
    }

    @PostMapping
    public Alert createAlert(@RequestBody Alert alert) {
        return service.save(alert);
    }

    @GetMapping
    public List<Alert> getAllAlerts() {
        return service.getAllAlerts();
    }
}