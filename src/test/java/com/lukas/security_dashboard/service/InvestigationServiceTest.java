package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.dto.InvestigationDetails;
import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.repository.AlertEvidenceRepository;
import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.LogEventRepository;
import com.lukas.security_dashboard.repository.ThreatIntelligenceDetectionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InvestigationServiceTest {

    private LogEventRepository logEventRepository;
    private AlertRepository alertRepository;
    private AlertEvidenceRepository alertEvidenceRepository;
    private InvestigationService investigationService;

    @BeforeEach
    void setUp() {
        logEventRepository = mock(LogEventRepository.class);
        alertRepository = mock(AlertRepository.class);
        alertEvidenceRepository = mock(AlertEvidenceRepository.class);
        investigationService = new InvestigationService(
                logEventRepository,
                alertRepository,
                mock(ThreatIntelligenceDetectionRepository.class),
                alertEvidenceRepository
        );
    }

    @Test
    void alertInvestigationIncludesRuleAssetsAndSupportingEvents() {
        LocalDateTime detectedAt = LocalDateTime.now();
        Alert alert = new Alert();
        alert.setId(8L);
        alert.setSeverity("HIGH");
        alert.setCreatedAt(detectedAt);
        alert.setTriggeringRule("Brute Force Threshold");
        alert.setSourceIp("203.0.113.8");
        alert.setUsername("analyst-target");
        alert.setDescription("Potential brute force detected.");

        LogEvent evidence = new LogEvent();
        evidence.setId(21L);
        evidence.setTimestamp(detectedAt.minusMinutes(1));
        evidence.setSourceIp("203.0.113.8");
        evidence.setUsername("analyst-target");
        evidence.setEventType("LOGIN_FAILED");

        when(alertRepository.findById(8L)).thenReturn(Optional.of(alert));
        when(alertEvidenceRepository.findLogEventsByAlertId(8L))
                .thenReturn(List.of(evidence));

        InvestigationDetails.Alert details = investigationService.investigateAlert(8L);

        assertEquals("HIGH", details.severity());
        assertEquals("Brute Force Threshold", details.triggeringRule());
        assertEquals(List.of("203.0.113.8"), details.affectedSourceIps());
        assertEquals(List.of("analyst-target"), details.affectedUsernames());
        assertEquals(1, details.ipIntelligence().size());
        assertEquals(1, details.supportingEvents().size());
        assertEquals(21L, details.supportingEvents().get(0).id());
        verify(logEventRepository, never())
                .findAllBySourceIpAndTimestampLessThanEqualAndEventTypeOrderByTimestampAsc(
                        "203.0.113.8",
                        detectedAt,
                        "LOGIN_FAILED"
                );
    }
}
