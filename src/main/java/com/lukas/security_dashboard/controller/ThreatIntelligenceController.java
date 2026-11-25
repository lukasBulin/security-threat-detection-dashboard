package com.lukas.security_dashboard.controller;

import com.lukas.security_dashboard.dto.ThreatIndicatorImportResult;
import com.lukas.security_dashboard.model.ThreatIntelligenceDetection;
import com.lukas.security_dashboard.service.ThreatIntelligenceService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/threat-intelligence")
public class ThreatIntelligenceController {

    private final ThreatIntelligenceService threatIntelligenceService;

    public ThreatIntelligenceController(ThreatIntelligenceService threatIntelligenceService) {
        this.threatIntelligenceService = threatIntelligenceService;
    }

    @GetMapping("/detections")
    public List<ThreatIntelligenceDetection> getRecentDetections() {
        return threatIntelligenceService.getRecentDetections();
    }

    @PostMapping(value = "/indicators/import", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ThreatIndicatorImportResult importIndicators(
            @RequestParam("file") MultipartFile file
    ) {
        return threatIntelligenceService.importCsv(file);
    }
}
