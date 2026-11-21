package com.lukas.security_dashboard.controller;

import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.service.LogEventService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/logs")
public class LogEventController {

    private final LogEventService service;

    public LogEventController(LogEventService service) {
        this.service = service;
    }

    @PostMapping
    public LogEvent createLog(@RequestBody LogEvent logEvent) {
        return service.save(logEvent);
    }

    @GetMapping
    public  List<LogEvent> getAllLogs() {
        return service.getAllLogs();
    }
}
