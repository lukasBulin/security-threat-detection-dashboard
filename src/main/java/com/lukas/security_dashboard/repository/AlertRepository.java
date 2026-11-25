package com.lukas.security_dashboard.repository;

import com.lukas.security_dashboard.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    List<Alert> findTop100BySourceIpOrderByCreatedAtDesc(String sourceIp);

    List<Alert> findTop100ByUsernameOrderByCreatedAtDesc(String username);

    @Query("""
        SELECT l.severity, COUNT(l)
        FROM Alert l
        GROUP BY l.severity
        ORDER BY COUNT(l) DESC
    """)
    List<Object[]> getAlertSeverityDistribution();

    @Query(value = """
        SELECT date_trunc(:bucket, created_at) AS time_bucket,
               UPPER(severity) AS alert_severity,
               COUNT(*) AS alert_count
        FROM alert
        WHERE created_at >= :since
          AND created_at <= :until
          AND UPPER(severity) IN ('HIGH', 'CRITICAL')
        GROUP BY date_trunc(:bucket, created_at), UPPER(severity)
        ORDER BY time_bucket
        """, nativeQuery = true)
    List<Object[]> getAlertTimeline(
            @Param("bucket") String bucket,
            @Param("since") LocalDateTime since,
            @Param("until") LocalDateTime until
    );
}