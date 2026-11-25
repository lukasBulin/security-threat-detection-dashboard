package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.LogEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class LogEventService {

    private final LogEventRepository repository;
    private final ThreatDetectionService threatDetectionService;
    private final AlertRepository alertRepository;
    private final ThreatIntelligenceService threatIntelligenceService;
    private final AlertEvidenceService alertEvidenceService;

    public LogEventService(
            LogEventRepository repository,
            ThreatDetectionService threatDetectionService,
            AlertRepository alertRepository,
            ThreatIntelligenceService threatIntelligenceService,
            AlertEvidenceService alertEvidenceService) {
        this.repository = repository;
        this.threatDetectionService = threatDetectionService;
        this.alertRepository = alertRepository;
        this.threatIntelligenceService = threatIntelligenceService;
        this.alertEvidenceService = alertEvidenceService;
    }

    @Transactional
    public LogEvent save(LogEvent logEvent) {

        LogEvent savedLog = repository.save(logEvent);

        AlertDetectionResult detection = threatDetectionService.analyzeLog(savedLog);

        if (detection != null) {
            Alert savedAlert = alertRepository.save(detection.alert());
            alertEvidenceService.linkEvidence(savedAlert, detection.evidenceEvents());
        }

        threatIntelligenceService.evaluateEvent(savedLog);

        return savedLog;
    }

    public List<LogEvent> getAllLogs() {
        return repository.findAll();
    }
}
