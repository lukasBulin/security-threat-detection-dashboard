package com.lukas.security_dashboard.controller;

import com.lukas.security_dashboard.service.AnalyticsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("api/analytics")
public class AnalyticsController {

    private final AnalyticsService analyticsService;

    public AnalyticsController(AnalyticsService analyticsService) {
        this.analyticsService = analyticsService;
    }

    @GetMapping("/top-ips")
    public List<Object[]> getTopAttackingIps() {
        return analyticsService.getTopAttackingIps();
    }

    @GetMapping("/top-users")
    public List<Object[]> getTopTargetedUsers() {
        return analyticsService.getTopTargetedUsers();
    }

    @GetMapping("/event-distribution")
    public List<Object[]> getEventDistribution() {
        return analyticsService.getEventDistribution();
    }

    @GetMapping("/alert-severity")
    public List<Object[]> getAlertSeverityDistribution() {
        return analyticsService.getAlertSeverityDistribution();
    }

}
