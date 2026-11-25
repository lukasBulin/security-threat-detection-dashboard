package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.repository.LogEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ThreatDetectionServiceTest {

    private LogEventRepository logEventRepository;
    private ThreatDetectionService threatDetectionService;

    @BeforeEach
    void setUp() {
        logEventRepository = mock(LogEventRepository.class);
        threatDetectionService = new ThreatDetectionService(logEventRepository);
    }

    @Test
    void bruteForceAlertIncludesTheFiveFailedLoginEvidenceEvents() {
        String sourceIp = "192.168.1.100";
        when(logEventRepository.countBySourceIpAndEventType(sourceIp, "LOGIN_FAILED"))
                .thenReturn(5L);
        when(logEventRepository.findTop5BySourceIpAndEventTypeOrderByIdDesc(
                sourceIp,
                "LOGIN_FAILED"
        )).thenReturn(List.of(
                failedLogin(5L, sourceIp),
                failedLogin(4L, sourceIp),
                failedLogin(3L, sourceIp),
                failedLogin(2L, sourceIp),
                failedLogin(1L, sourceIp)
        ));

        AlertDetectionResult result = threatDetectionService.analyzeLog(
                failedLogin(5L, sourceIp)
        );

        assertNotNull(result);
        assertEquals("HIGH", result.alert().getSeverity());
        assertEquals("Brute Force Threshold", result.alert().getTriggeringRule());
        assertEquals(List.of(1L, 2L, 3L, 4L, 5L), result.evidenceEvents()
                .stream()
                .map(LogEvent::getId)
                .toList());
    }

    private LogEvent failedLogin(Long id, String sourceIp) {
        LogEvent event = new LogEvent();
        event.setId(id);
        event.setSourceIp(sourceIp);
        event.setEventType("LOGIN_FAILED");
        return event;
    }
}
