package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.repository.LogEventRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class ThreatDetectionService {

    private final LogEventRepository logEventRepository;

    public ThreatDetectionService(LogEventRepository logEventRepository) {
        this.logEventRepository = logEventRepository;
    }

    public Alert analyzeLog(LogEvent logEvent) {

        long failedCount = logEventRepository.countBySourceIpAndEventType(
                logEvent.getSourceIp(),
                "LOGIN_FAILED"
        );

        System.out.println("Failed Count = " + failedCount);

        Alert alert = new Alert();

        if (failedCount == 5) {

            alert.setSeverity("HIGH");
            alert.setDescription("Potential brute force attack detected from IP: "
                                + logEvent.getSourceIp());

            alert.setCreatedAt(LocalDateTime.now());

            return alert;
        }

        if ("LOGIN_SUCCESS".equals(logEvent.getEventType()) && failedCount >= 5)
        {
            alert.setSeverity("CRITICAL");
            alert.setDescription("Possible account compromise from IP: "
            + logEvent.getSourceIp());

            return alert;
        }

        return null;
    }
}
