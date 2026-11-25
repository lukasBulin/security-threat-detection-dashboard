package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.AlertEvidence;
import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.repository.AlertEvidenceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class AlertEvidenceService {

    private final AlertEvidenceRepository alertEvidenceRepository;

    public AlertEvidenceService(AlertEvidenceRepository alertEvidenceRepository) {
        this.alertEvidenceRepository = alertEvidenceRepository;
    }

    @Transactional
    public void linkEvidence(Alert alert, List<LogEvent> events) {
        if (alert.getId() == null) {
            throw new IllegalStateException("Alert must be persisted before linking evidence.");
        }

        Map<Long, LogEvent> uniqueEvents = new LinkedHashMap<>();
        for (LogEvent event : events) {
            if (event.getId() == null) {
                throw new IllegalStateException("Evidence log event must be persisted.");
            }
            uniqueEvents.putIfAbsent(event.getId(), event);
        }

        List<AlertEvidence> links = uniqueEvents.values().stream()
                .map(event -> new AlertEvidence(alert, event))
                .toList();
        if (!links.isEmpty()) {
            alertEvidenceRepository.saveAll(links);
        }
    }
}
