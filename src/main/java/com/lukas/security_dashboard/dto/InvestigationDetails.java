package com.lukas.security_dashboard.dto;

import java.time.LocalDateTime;
import java.util.List;

public final class InvestigationDetails {

    private InvestigationDetails() {
    }

    public record ActivityEvent(
            Long id,
            LocalDateTime timestamp,
            String sourceIp,
            String username,
            String eventType
    ) {
    }

    public record RelatedAlert(
            Long id,
            String severity,
            String description,
            LocalDateTime createdAt,
            String triggeringRule
    ) {
    }

    public record ThreatMatch(
            Long id,
            String ipAddress,
            String threatType,
            int reputationScore,
            LocalDateTime detectedAt,
            String associatedEvent
    ) {
    }

    public record Ip(
            String ipAddress,
            long failedLogins,
            long successfulLogins,
            LocalDateTime firstSeen,
            LocalDateTime lastSeen,
            List<RelatedAlert> relatedAlerts,
            List<ThreatMatch> threatMatches,
            List<ActivityEvent> activityTimeline
    ) {
    }

    public record User(
            String username,
            long failedLogins,
            long successfulLogins,
            long accountLockouts,
            List<String> sourceIps,
            List<RelatedAlert> relatedAlerts,
            List<ActivityEvent> activityTimeline
    ) {
    }

    public record Alert(
            Long id,
            String severity,
            LocalDateTime detectionTime,
            String triggeringRule,
            String description,
            List<String> affectedSourceIps,
            List<String> affectedUsernames,
            List<Ip> ipIntelligence,
            List<ActivityEvent> supportingEvents
    ) {
    }
}
