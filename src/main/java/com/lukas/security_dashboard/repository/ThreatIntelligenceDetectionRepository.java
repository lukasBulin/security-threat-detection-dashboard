package com.lukas.security_dashboard.repository;

import com.lukas.security_dashboard.model.ThreatIntelligenceDetection;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ThreatIntelligenceDetectionRepository
        extends JpaRepository<ThreatIntelligenceDetection, Long> {
    List<ThreatIntelligenceDetection> findTop100ByOrderByDetectedAtDesc();

    List<ThreatIntelligenceDetection> findTop100ByIpAddressOrderByDetectedAtDesc(String ipAddress);

    boolean existsByEventId(Long eventId);
}
