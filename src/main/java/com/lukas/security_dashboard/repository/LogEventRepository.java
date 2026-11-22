package com.lukas.security_dashboard.repository;

import com.lukas.security_dashboard.model.LogEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface LogEventRepository extends JpaRepository<LogEvent, Long> {

    long countBySourceIpAndEventType(String sourceIp, String eventType);

    long countByEventType(String eventType);

    long countDistinctBySourceIpIsNotNull();

    long countDistinctByUsernameIsNotNull();

    @Query("""
        SELECT l.sourceIp, COUNT(l)
        FROM LogEvent l
        WHERE l.eventType = 'LOGIN_FAILED'
        GROUP BY l.sourceIp
        ORDER BY COUNT(l) DESC
    """)
    List<Object[]> findTopAttackingIps();

    @Query("""
        SELECT l.username, COUNT(l)
        FROM LogEvent l
        WHERE l.eventType = 'LOGIN_FAILED'
        GROUP BY l.username
        ORDER BY COUNT(l) DESC
    """)
    List<Object[]> findTopTargetedUsers();

    @Query("""
        SELECT l.eventType, COUNT(l)
        FROM LogEvent l
        GROUP BY l.eventType
        ORDER BY COUNT(l) DESC
    """)
    List<Object[]> getEventDistribution();
}