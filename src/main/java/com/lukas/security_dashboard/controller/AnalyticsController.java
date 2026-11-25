package com.lukas.security_dashboard.controller;

import com.lukas.security_dashboard.service.AnalyticsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import com.lukas.security_dashboard.dto.AlertTimelinePoint;

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

    @GetMapping("/alert-timeline")
    public List<AlertTimelinePoint> getAlertTimeline(
            @RequestParam(defaultValue = "24h") String range
    ) {
        return analyticsService.getAlertTimeline(range);
    }

}
