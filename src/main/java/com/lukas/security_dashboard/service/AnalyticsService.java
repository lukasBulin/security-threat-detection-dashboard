package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.LogEventRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AnalyticsService {

    private final LogEventRepository repository;
    private final AlertRepository alertRepository;

    public AnalyticsService(LogEventRepository repository, AlertRepository alertRepository) {
        this.repository = repository;
        this.alertRepository = alertRepository;
    }

    public List<Object[]> getTopAttackingIps() {
        return repository.findTopAttackingIps();
    }

    public List<Object[]> getTopTargetedUsers() {
        return repository.findTopTargetedUsers();
    }

    public List<Object[]> getEventDistribution() {
        return repository.getEventDistribution();
    }

    public List<Object[]> getAlertSeverityDistribution() {
        return alertRepository.getAlertSeverityDistribution();
    }
}
