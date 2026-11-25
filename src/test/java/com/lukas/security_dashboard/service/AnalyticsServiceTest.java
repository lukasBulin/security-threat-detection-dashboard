package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.dto.AlertTimelinePoint;
import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.LogEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AnalyticsServiceTest {

    private AlertRepository alertRepository;
    private AnalyticsService analyticsService;

    @BeforeEach
    void setUp() {
        alertRepository = mock(AlertRepository.class);
        analyticsService = new AnalyticsService(
                mock(LogEventRepository.class),
                alertRepository
        );
    }

    @Test
    void alertTimelineGroupsHourlyCountsAndFillsEmptyBuckets() {
        when(alertRepository.getAlertTimeline(
                eq("hour"),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        ))
                .thenAnswer(invocation -> {
                    LocalDateTime firstBucket = invocation.getArgument(1);
                    return List.<Object[]>of(
                            new Object[]{Timestamp.valueOf(firstBucket), "HIGH", 3L},
                            new Object[]{Timestamp.valueOf(firstBucket), "CRITICAL", 1L},
                            new Object[]{
                                    Timestamp.valueOf(firstBucket.plusHours(1)),
                                    "HIGH",
                                    2L
                            }
                    );
                });

        List<AlertTimelinePoint> timeline = analyticsService.getAlertTimeline("24h");

        assertEquals(24, timeline.size());
        assertEquals(3, timeline.get(0).high());
        assertEquals(1, timeline.get(0).critical());
        assertEquals(2, timeline.get(1).high());
        assertEquals(0, timeline.get(1).critical());
        assertEquals(0, timeline.get(2).high());
        assertEquals(0, timeline.get(2).critical());
    }

    @Test
    void sevenDayRangeUsesDailyBuckets() {
        when(alertRepository.getAlertTimeline(
                eq("day"),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        ))
                .thenReturn(List.of());

        List<AlertTimelinePoint> timeline = analyticsService.getAlertTimeline("7d");

        assertEquals(7, timeline.size());
        assertEquals(0, timeline.get(6).timestamp().getHour());
        assertEquals(timeline.get(0).timestamp().plusDays(6), timeline.get(6).timestamp());
    }

    @Test
    void unsupportedTimelineRangeReturnsBadRequest() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> analyticsService.getAlertTimeline("90d")
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
    }
}
