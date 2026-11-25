package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.model.ThreatIndicator;
import com.lukas.security_dashboard.model.ThreatIntelligenceDetection;
import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.ThreatIndicatorRepository;
import com.lukas.security_dashboard.repository.ThreatIntelligenceDetectionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ThreatIntelligenceServiceTest {

    private ThreatIndicatorRepository indicatorRepository;
    private ThreatIntelligenceDetectionRepository detectionRepository;
    private AlertRepository alertRepository;
    private AlertEvidenceService alertEvidenceService;
    private ThreatIntelligenceService service;

    @BeforeEach
    void setUp() {
        indicatorRepository = mock(ThreatIndicatorRepository.class);
        detectionRepository = mock(ThreatIntelligenceDetectionRepository.class);
        alertRepository = mock(AlertRepository.class);
        alertEvidenceService = mock(AlertEvidenceService.class);
        service = new ThreatIntelligenceService(
                indicatorRepository,
                detectionRepository,
                alertRepository,
                alertEvidenceService
        );
    }

    @Test
    void importsIndicatorsAndNormalizesIpv4Addresses() {
        MockMultipartFile file = csv(
                "ip_address,threat_type,reputation_score\n"
                        + "203.0.113.008,botnet,91\n"
                        + "203.0.113.8,credential stuffing,75\n"
        );
        when(indicatorRepository.findAllByIpAddressIn(anyCollection())).thenReturn(List.of());

        var result = service.importCsv(file);

        assertEquals(1, result.importedCount());
        assertEquals(0, result.updatedCount());
        verify(indicatorRepository).saveAll(any());
    }

    @Test
    void rejectsInvalidCsvIpAddress() {
        MockMultipartFile file = csv(
                "ip_address,threat_type,reputation_score\n"
                        + "203.0.113.256,botnet,91\n"
        );

        assertThrows(ResponseStatusException.class, () -> service.importCsv(file));
    }

    @Test
    void matchingEventCreatesDetectionAndCriticalAlert() {
        ThreatIndicator indicator = new ThreatIndicator();
        indicator.setIpAddress("203.0.113.8");
        indicator.setThreatType("botnet");
        indicator.setReputationScore(91);
        LogEvent event = new LogEvent();
        event.setId(7L);
        event.setSourceIp("203.0.113.8");
        event.setEventType("LOGIN_FAILED");
        when(detectionRepository.existsByEventId(7L)).thenReturn(false);
        when(indicatorRepository.findByIpAddress("203.0.113.8"))
                .thenReturn(Optional.of(indicator));
        when(alertRepository.save(any(Alert.class))).thenAnswer(invocation -> {
            Alert alert = invocation.getArgument(0);
            alert.setId(12L);
            return alert;
        });

        service.evaluateEvent(event);

        verify(detectionRepository).save(any(ThreatIntelligenceDetection.class));
        ArgumentCaptor<Alert> alertCaptor = ArgumentCaptor.forClass(Alert.class);
        verify(alertRepository).save(alertCaptor.capture());
        assertEquals("CRITICAL", alertCaptor.getValue().getSeverity());
        assertEquals("Threat intelligence match: botnet IP 203.0.113.8 "
                        + "(reputation 91/100) observed in LOGIN_FAILED.",
                alertCaptor.getValue().getDescription());
        verify(alertEvidenceService).linkEvidence(alertCaptor.getValue(), List.of(event));
    }

    private MockMultipartFile csv(String contents) {
        return new MockMultipartFile(
                "file",
                "indicators.csv",
                "text/csv",
                contents.getBytes(StandardCharsets.UTF_8)
        );
    }
}
