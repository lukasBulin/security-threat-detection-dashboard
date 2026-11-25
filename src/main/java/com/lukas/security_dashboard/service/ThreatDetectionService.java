package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.repository.LogEventRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

@Service
public class ThreatDetectionService {

    private final LogEventRepository logEventRepository;

    public ThreatDetectionService(LogEventRepository logEventRepository) {
        this.logEventRepository = logEventRepository;
    }

    public AlertDetectionResult analyzeLog(LogEvent logEvent) {

        long failedCount = logEventRepository.countBySourceIpAndEventType(
                logEvent.getSourceIp(),
                "LOGIN_FAILED"
        );

        if ("LOGIN_SUCCESS".equals(logEvent.getEventType()) && failedCount >= 5) {
            List<LogEvent> evidenceEvents = getFailedLoginEvidence(logEvent);
            evidenceEvents.add(logEvent);
            return createAlert(
                    logEvent,
                    "CRITICAL",
                    "Possible account compromise from IP: " + logEvent.getSourceIp(),
                    "Possible Account Compromise",
                    evidenceEvents
            );
        }

        if (failedCount == 5) {
            return createAlert(
                    logEvent,
                    "HIGH",
                    "Potential brute force attack detected from IP: " + logEvent.getSourceIp(),
                    "Brute Force Threshold",
                    getFailedLoginEvidence(logEvent)
            );
        }

        return null;
    }

    private AlertDetectionResult createAlert(
            LogEvent logEvent,
            String severity,
            String description,
            String triggeringRule,
            List<LogEvent> evidenceEvents
    ) {
        Alert alert = new Alert();
        alert.setSeverity(severity);
        alert.setDescription(description);
        alert.setCreatedAt(LocalDateTime.now());
        alert.setTriggeringRule(triggeringRule);
        alert.setSourceIp(logEvent.getSourceIp());
        alert.setUsername(logEvent.getUsername());
        alert.setEventId(logEvent.getId());
        evidenceEvents.sort(Comparator.comparing(LogEvent::getId));
        return new AlertDetectionResult(alert, List.copyOf(evidenceEvents));
    }

    private List<LogEvent> getFailedLoginEvidence(LogEvent logEvent) {
        return new ArrayList<>(logEventRepository
                .findTop5BySourceIpAndEventTypeOrderByIdDesc(
                        logEvent.getSourceIp(),
                        "LOGIN_FAILED"
                )
                .stream()
                .sorted(Comparator.comparing(LogEvent::getId))
                .toList());
    }
}
