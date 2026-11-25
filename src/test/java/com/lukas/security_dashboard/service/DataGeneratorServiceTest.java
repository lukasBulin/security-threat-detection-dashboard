package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.LogEvent;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class DataGeneratorServiceTest {

    @Test
    void generatesMostlyLegitimateTrafficAndContiguousDetectableAttackScenarios() {
        LogEventService logEventService = mock(LogEventService.class);
        DataGeneratorService generator = new DataGeneratorService(logEventService);

        generator.generateLogs(110);

        ArgumentCaptor<LogEvent> eventCaptor = ArgumentCaptor.forClass(LogEvent.class);
        verify(logEventService, times(110)).save(eventCaptor.capture());
        List<LogEvent> events = eventCaptor.getAllValues();
        List<LogEvent> legitimateEvents = events.stream()
                .filter(event -> event.getSourceIp().startsWith("10.0.0."))
                .toList();
        Map<String, List<LogEvent>> attackScenarios = new LinkedHashMap<>();
        for (LogEvent event : events) {
            if (event.getSourceIp().startsWith("198.18.")
                    || event.getSourceIp().startsWith("198.19.")) {
                attackScenarios.computeIfAbsent(event.getSourceIp(), ignored -> new ArrayList<>())
                        .add(event);
            }
        }

        assertEquals(99, legitimateEvents.size());
        assertTrue(legitimateEvents.stream().allMatch(event ->
                List.of("LOGIN_SUCCESS", "PASSWORD_RESET", "ACCOUNT_LOCKED")
                        .contains(event.getEventType())));
        assertEquals(2, attackScenarios.size());

        long bruteForceScenarios = 0;
        long compromiseScenarios = 0;
        for (List<LogEvent> scenario : attackScenarios.values()) {
            long failedLogins = scenario.stream()
                    .filter(event -> "LOGIN_FAILED".equals(event.getEventType()))
                    .count();
            assertEquals(5, failedLogins);
            assertEquals(1, scenario.stream().map(LogEvent::getUsername).distinct().count());

            if (scenario.size() == 5) {
                bruteForceScenarios++;
            } else {
                assertEquals(6, scenario.size());
                assertEquals("LOGIN_SUCCESS", scenario.get(5).getEventType());
                compromiseScenarios++;
            }
        }

        assertEquals(1, bruteForceScenarios);
        assertEquals(1, compromiseScenarios);
    }
}
