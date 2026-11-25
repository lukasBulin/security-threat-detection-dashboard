package com.lukas.security_dashboard.repository;

import com.lukas.security_dashboard.model.LogEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface LogEventRepository extends JpaRepository<LogEvent, Long> {

    long countBySourceIpAndEventType(String sourceIp, String eventType);

    List<LogEvent> findTop5BySourceIpAndEventTypeOrderByIdDesc(
            String sourceIp,
            String eventType
    );

    long countByUsernameAndEventType(String username, String eventType);

    long countByEventType(String eventType);

    List<LogEvent> findTop100BySourceIpAndTimestampIsNotNullOrderByTimestampDesc(String sourceIp);

    List<LogEvent> findTop100ByUsernameAndTimestampIsNotNullOrderByTimestampDesc(String username);

    List<LogEvent> findAllBySourceIpAndTimestampLessThanEqualAndEventTypeOrderByTimestampAsc(
            String sourceIp,
            LocalDateTime timestamp,
            String eventType
    );

    List<LogEvent> findAllBySourceIpAndTimestampLessThanEqualOrderByTimestampAsc(
            String sourceIp,
            LocalDateTime timestamp
    );

    List<LogEvent> findAllByUsernameAndTimestampLessThanEqualOrderByTimestampAsc(
            String username,
            LocalDateTime timestamp
    );

    @Query("""
        SELECT DISTINCT l.sourceIp
        FROM LogEvent l
        WHERE l.username = :username AND l.sourceIp IS NOT NULL
        ORDER BY l.sourceIp
    """)
    List<String> findDistinctSourceIpsByUsername(@Param("username") String username);

    Optional<LogEvent> findFirstBySourceIpAndTimestampIsNotNullOrderByTimestampAsc(String sourceIp);

    Optional<LogEvent> findFirstBySourceIpAndTimestampIsNotNullOrderByTimestampDesc(String sourceIp);

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