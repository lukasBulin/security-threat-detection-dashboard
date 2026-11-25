package com.lukas.security_dashboard.dto;

import java.time.LocalDateTime;

public record AlertTimelinePoint(
        LocalDateTime timestamp,
        long high,
        long critical
) {
}
