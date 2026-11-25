package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.LogEvent;

import java.util.List;

public record AlertDetectionResult(Alert alert, List<LogEvent> evidenceEvents) {
}
