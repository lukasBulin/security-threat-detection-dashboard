package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.LogEventRepository;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class StatsService {

    private final LogEventRepository logEventRepository;
    private final AlertRepository alertRepository;

    public StatsService(LogEventRepository logEventRepository, AlertRepository alertRepository      ) {
        this.logEventRepository = logEventRepository;
        this.alertRepository = alertRepository;
    }

    public Map<String, Long> getStats() {

        Map<String, Long> stats = new HashMap<>();

        stats.put("totalLogs", logEventRepository.count());
        stats.put("totalAlerts", alertRepository.count());

        stats.put("failedLogins",
                logEventRepository.countByEventType("LOGIN_FAILED"));
        stats.put("successfulLogins",
                logEventRepository.countByEventType("LOGIN_SUCCESS"));
        stats.put("passwordResets",
                logEventRepository.countByEventType("PASSWORD_RESET"));
        stats.put("accountLockouts",
                logEventRepository.countByEventType("ACCOUNT_LOCKED"));
        stats.put("uniqueIps",
                logEventRepository.countDistinctBySourceIpIsNotNull());
        stats.put("uniqueUsers",
                logEventRepository.countDistinctByUsernameIsNotNull());

        return stats;
    }
}
