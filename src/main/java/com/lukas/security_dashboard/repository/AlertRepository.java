package com.lukas.security_dashboard.repository;

import com.lukas.security_dashboard.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    @Query("""
        SELECT l.severity, COUNT(l)
        FROM Alert l
        GROUP BY l.severity
        ORDER BY COUNT(l) DESC
    """)
    List<Object[]> getAlertSeverityDistribution();
}