package com.lukas.security_dashboard.repository;

import com.lukas.security_dashboard.model.LogEvent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LogEventRepository extends JpaRepository<LogEvent, Long> {

    long countBySourceIpAndEventType(String sourceIp, String eventType);
}