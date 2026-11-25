package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.dto.AlertTimelinePoint;
import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.LogEventRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

@Service
public class AnalyticsService {

    private final LogEventRepository repository;
    private final AlertRepository alertRepository;

    public AnalyticsService(LogEventRepository repository, AlertRepository alertRepository) {
        this.repository = repository;
        this.alertRepository = alertRepository;
    }

    public List<Object[]> getTopAttackingIps() {
        return repository.findTopAttackingIps();
    }

    public List<Object[]> getTopTargetedUsers() {
        return repository.findTopTargetedUsers();
    }

    public List<Object[]> getEventDistribution() {
        return repository.getEventDistribution();
    }

    public List<Object[]> getAlertSeverityDistribution() {
        return alertRepository.getAlertSeverityDistribution();
    }

    public List<AlertTimelinePoint> getAlertTimeline(String range) {
        LocalDateTime now = LocalDateTime.now();
        String bucket;
        LocalDateTime firstBucket;
        int bucketCount;

        switch (range.toLowerCase(Locale.ROOT)) {
            case "24h" -> {
                bucket = "hour";
                bucketCount = 24;
                firstBucket = now.truncatedTo(ChronoUnit.HOURS).minusHours(bucketCount - 1);
            }
            case "7d" -> {
                bucket = "day";
                bucketCount = 7;
                firstBucket = now.toLocalDate().minusDays(bucketCount - 1L).atStartOfDay();
            }
            case "30d" -> {
                bucket = "day";
                bucketCount = 30;
                firstBucket = now.toLocalDate().minusDays(bucketCount - 1L).atStartOfDay();
            }
            default -> throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Unsupported range. Use 24h, 7d, or 30d."
            );
        }

        Map<LocalDateTime, long[]> countsByBucket = new TreeMap<>();
        for (int index = 0; index < bucketCount; index++) {
            LocalDateTime timeBucket = bucket.equals("hour")
                    ? firstBucket.plusHours(index)
                    : firstBucket.plusDays(index);
            countsByBucket.put(timeBucket, new long[2]);
        }

        for (Object[] row : alertRepository.getAlertTimeline(bucket, firstBucket, now)) {
            LocalDateTime timeBucket = toLocalDateTime(row[0]);
            String severity = row[1].toString().toUpperCase(Locale.ROOT);
            int severityIndex = switch (severity) {
                case "HIGH" -> 0;
                case "CRITICAL" -> 1;
                default -> throw new IllegalStateException(
                        "Unexpected alert severity in timeline query: " + severity
                );
            };
            long[] bucketCounts = countsByBucket.get(timeBucket);
            if (bucketCounts != null) {
                bucketCounts[severityIndex] = ((Number) row[2]).longValue();
            }
        }

        return countsByBucket.entrySet().stream()
                .map(entry -> new AlertTimelinePoint(
                        entry.getKey(),
                        entry.getValue()[0],
                        entry.getValue()[1]
                ))
                .toList();
    }

    private LocalDateTime toLocalDateTime(Object value) {
        if (value instanceof Timestamp timestamp) {
            return timestamp.toLocalDateTime();
        }
        if (value instanceof LocalDateTime dateTime) {
            return dateTime;
        }
        throw new IllegalStateException(
                "Unexpected timestamp type in alert timeline query: " + value.getClass().getName()
        );
    }
}
