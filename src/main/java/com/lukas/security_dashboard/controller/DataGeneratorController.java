package com.lukas.security_dashboard.controller;

import com.lukas.security_dashboard.service.DataGeneratorService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/generate")
public class DataGeneratorController {

    private final DataGeneratorService service;

    public DataGeneratorController(DataGeneratorService service) {
        this.service = service;
    }

    @PostMapping
    public String generateData(
            @RequestParam int count) {

        service.generateLogs(count);

        return count + " logs generated successfully";
    }
}
