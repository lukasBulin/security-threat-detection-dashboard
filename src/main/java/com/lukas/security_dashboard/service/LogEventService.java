package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.LogEventRepository;
import lombok.extern.java.Log;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LogEventService {

    private final LogEventRepository repository;
    private final ThreatDetectionService threatDetectionService;
    private final AlertRepository alertRepository;

    public LogEventService(
            LogEventRepository repository,
            ThreatDetectionService threatDetectionService,
            AlertRepository alertRepository) {
        this.repository = repository;
        this.threatDetectionService = threatDetectionService;
        this.alertRepository = alertRepository;
    }

    public LogEvent save(LogEvent logEvent) {

        LogEvent savedLog = repository.save(logEvent);

        Alert alert = threatDetectionService.analyzeLog(logEvent);

        if (alert != null)
        {
            alertRepository.save(alert);
        }

        return savedLog;
    }

    public List<LogEvent> getAllLogs() {
        return repository.findAll();
    }
}
