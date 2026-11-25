package com.lukas.security_dashboard.repository;

import com.lukas.security_dashboard.model.AlertEvidence;
import com.lukas.security_dashboard.model.LogEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface AlertEvidenceRepository extends JpaRepository<AlertEvidence, Long> {

    @Query("""
        SELECT evidence.logEvent
        FROM AlertEvidence evidence
        WHERE evidence.alert.id = :alertId
        ORDER BY evidence.logEvent.id
    """)
    List<LogEvent> findLogEventsByAlertId(@Param("alertId") Long alertId);
}
