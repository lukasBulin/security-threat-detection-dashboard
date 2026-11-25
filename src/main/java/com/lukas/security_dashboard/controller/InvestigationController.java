package com.lukas.security_dashboard.controller;

import com.lukas.security_dashboard.dto.InvestigationDetails;
import com.lukas.security_dashboard.service.InvestigationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/investigations")
public class InvestigationController {

    private final InvestigationService investigationService;

    public InvestigationController(InvestigationService investigationService) {
        this.investigationService = investigationService;
    }

    @GetMapping("/ip")
    public InvestigationDetails.Ip investigateIp(@RequestParam String address) {
        return investigationService.investigateIp(address);
    }

    @GetMapping("/username")
    public InvestigationDetails.User investigateUser(@RequestParam String username) {
        return investigationService.investigateUser(username);
    }

    @GetMapping("/alert/{alertId}")
    public InvestigationDetails.Alert investigateAlert(@PathVariable Long alertId) {
        return investigationService.investigateAlert(alertId);
    }
}
