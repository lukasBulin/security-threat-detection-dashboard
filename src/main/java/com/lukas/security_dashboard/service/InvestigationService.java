package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.dto.InvestigationDetails;
import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.model.ThreatIntelligenceDetection;
import com.lukas.security_dashboard.repository.AlertEvidenceRepository;
import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.LogEventRepository;
import com.lukas.security_dashboard.repository.ThreatIntelligenceDetectionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

@Service
public class InvestigationService {

    private static final String BRUTE_FORCE_RULE = "Brute Force Threshold";
    private static final String INTELLIGENCE_RULE = "Threat Intelligence IP Match";

    private final LogEventRepository logEventRepository;
    private final AlertRepository alertRepository;
    private final ThreatIntelligenceDetectionRepository detectionRepository;
    private final AlertEvidenceRepository alertEvidenceRepository;

    public InvestigationService(
            LogEventRepository logEventRepository,
            AlertRepository alertRepository,
            ThreatIntelligenceDetectionRepository detectionRepository,
            AlertEvidenceRepository alertEvidenceRepository
    ) {
        this.logEventRepository = logEventRepository;
        this.alertRepository = alertRepository;
        this.detectionRepository = detectionRepository;
        this.alertEvidenceRepository = alertEvidenceRepository;
    }

    public InvestigationDetails.Ip investigateIp(String ipAddress) {
        String normalizedIp = requireValue(ipAddress, "IP address");
        return getIpInvestigation(normalizedIp);
    }

    private InvestigationDetails.Ip getIpInvestigation(String normalizedIp) {
        List<LogEvent> activity = logEventRepository
                .findTop100BySourceIpAndTimestampIsNotNullOrderByTimestampDesc(normalizedIp);
        List<Alert> relatedAlerts = alertRepository
                .findTop100BySourceIpOrderByCreatedAtDesc(normalizedIp);
        List<ThreatIntelligenceDetection> threatMatches = detectionRepository
                .findTop100ByIpAddressOrderByDetectedAtDesc(normalizedIp);

        return new InvestigationDetails.Ip(
                normalizedIp,
                logEventRepository.countBySourceIpAndEventType(normalizedIp, "LOGIN_FAILED"),
                logEventRepository.countBySourceIpAndEventType(normalizedIp, "LOGIN_SUCCESS"),
                logEventRepository
                        .findFirstBySourceIpAndTimestampIsNotNullOrderByTimestampAsc(normalizedIp)
                        .map(LogEvent::getTimestamp)
                        .orElse(null),
                logEventRepository
                        .findFirstBySourceIpAndTimestampIsNotNullOrderByTimestampDesc(normalizedIp)
                        .map(LogEvent::getTimestamp)
                        .orElse(null),
                relatedAlerts.stream().map(this::toRelatedAlert).toList(),
                threatMatches.stream().map(this::toThreatMatch).toList(),
                toChronologicalEvents(activity)
        );
    }

    public InvestigationDetails.User investigateUser(String username) {
        String normalizedUsername = requireValue(username, "Username");
        List<LogEvent> activity = logEventRepository
                .findTop100ByUsernameAndTimestampIsNotNullOrderByTimestampDesc(normalizedUsername);
        List<Alert> relatedAlerts = alertRepository
                .findTop100ByUsernameOrderByCreatedAtDesc(normalizedUsername);
        List<String> sourceIps = logEventRepository
                .findDistinctSourceIpsByUsername(normalizedUsername)
                .stream()
                .filter(Objects::nonNull)
                .distinct()
                .sorted()
                .toList();

        return new InvestigationDetails.User(
                normalizedUsername,
                logEventRepository.countByUsernameAndEventType(normalizedUsername, "LOGIN_FAILED"),
                logEventRepository.countByUsernameAndEventType(normalizedUsername, "LOGIN_SUCCESS"),
                logEventRepository.countByUsernameAndEventType(normalizedUsername, "ACCOUNT_LOCKED"),
                sourceIps,
                relatedAlerts.stream().map(this::toRelatedAlert).toList(),
                toChronologicalEvents(activity)
        );
    }

    public InvestigationDetails.Alert investigateAlert(Long alertId) {
        Alert alert = alertRepository.findById(alertId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Alert not found."
                ));
        String triggeringRule = alert.getTriggeringRule();
        if (triggeringRule == null || triggeringRule.isBlank()) {
            triggeringRule = inferRule(alert.getDescription());
        }

        List<LogEvent> supportingEvents = findSupportingEvents(alert, triggeringRule);
        List<String> sourceIps = new ArrayList<>();
        if (alert.getSourceIp() != null && !alert.getSourceIp().isBlank()) {
            sourceIps.add(alert.getSourceIp());
        }
        supportingEvents.stream()
                .map(LogEvent::getSourceIp)
                .filter(ip -> ip != null && !ip.isBlank())
                .forEach(sourceIps::add);
        List<String> affectedSourceIps = sourceIps.stream().distinct().sorted().toList();

        List<String> usernames = new ArrayList<>();
        if (alert.getUsername() != null && !alert.getUsername().isBlank()) {
            usernames.add(alert.getUsername());
        }
        supportingEvents.stream()
                .map(LogEvent::getUsername)
                .filter(username -> username != null && !username.isBlank())
                .forEach(usernames::add);
        List<String> affectedUsernames = usernames.stream().distinct().sorted().toList();

        return new InvestigationDetails.Alert(
                alert.getId(),
                alert.getSeverity(),
                alert.getCreatedAt(),
                triggeringRule,
                alert.getDescription(),
                affectedSourceIps,
                affectedUsernames,
                affectedSourceIps.stream().map(this::getIpInvestigation).toList(),
                toChronologicalEvents(supportingEvents)
        );
    }

    private List<LogEvent> findSupportingEvents(Alert alert, String triggeringRule) {
        List<LogEvent> linkedEvents = alertEvidenceRepository
                .findLogEventsByAlertId(alert.getId());
        if (!linkedEvents.isEmpty()) {
            return linkedEvents;
        }

        if (INTELLIGENCE_RULE.equals(triggeringRule) && alert.getEventId() != null) {
            return logEventRepository.findById(alert.getEventId()).stream().toList();
        }
        if (alert.getSourceIp() == null || alert.getCreatedAt() == null) {
            return List.of();
        }
        if (BRUTE_FORCE_RULE.equals(triggeringRule)) {
            return logEventRepository
                    .findAllBySourceIpAndTimestampLessThanEqualAndEventTypeOrderByTimestampAsc(
                            alert.getSourceIp(),
                            alert.getCreatedAt(),
                            "LOGIN_FAILED"
                    );
        }
        return logEventRepository.findAllBySourceIpAndTimestampLessThanEqualOrderByTimestampAsc(
                alert.getSourceIp(),
                alert.getCreatedAt()
        );
    }

    private String inferRule(String description) {
        if (description == null) {
            return "Unspecified";
        }
        if (description.startsWith("Potential brute force")) {
            return BRUTE_FORCE_RULE;
        }
        if (description.startsWith("Possible account compromise")) {
            return "Possible Account Compromise";
        }
        if (description.startsWith("Threat intelligence match")) {
            return INTELLIGENCE_RULE;
        }
        return "Unspecified";
    }

    private List<InvestigationDetails.ActivityEvent> toChronologicalEvents(
            List<LogEvent> events
    ) {
        return events.stream()
                .sorted(Comparator.comparing(
                        LogEvent::getTimestamp,
                        Comparator.nullsFirst(Comparator.naturalOrder())
                ))
                .map(event -> new InvestigationDetails.ActivityEvent(
                        event.getId(),
                        event.getTimestamp(),
                        event.getSourceIp(),
                        event.getUsername(),
                        event.getEventType()
                ))
                .toList();
    }

    private InvestigationDetails.RelatedAlert toRelatedAlert(Alert alert) {
        return new InvestigationDetails.RelatedAlert(
                alert.getId(),
                alert.getSeverity(),
                alert.getDescription(),
                alert.getCreatedAt(),
                alert.getTriggeringRule()
        );
    }

    private InvestigationDetails.ThreatMatch toThreatMatch(
            ThreatIntelligenceDetection detection
    ) {
        return new InvestigationDetails.ThreatMatch(
                detection.getId(),
                detection.getIpAddress(),
                detection.getThreatType(),
                detection.getReputationScore(),
                detection.getDetectedAt(),
                detection.getAssociatedEvent()
        );
    }

    private String requireValue(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    label + " must not be empty."
            );
        }
        return value.trim();
    }
}
