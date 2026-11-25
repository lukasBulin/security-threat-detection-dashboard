package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.dto.ThreatIndicatorImportResult;
import com.lukas.security_dashboard.model.Alert;
import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.model.ThreatIndicator;
import com.lukas.security_dashboard.model.ThreatIntelligenceDetection;
import com.lukas.security_dashboard.repository.AlertRepository;
import com.lukas.security_dashboard.repository.ThreatIndicatorRepository;
import com.lukas.security_dashboard.repository.ThreatIntelligenceDetectionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class ThreatIntelligenceService {

    private static final long MAX_FILE_BYTES = 950_000;
    private static final int MAX_INDICATORS = 5_000;

    private final ThreatIndicatorRepository indicatorRepository;
    private final ThreatIntelligenceDetectionRepository detectionRepository;
    private final AlertRepository alertRepository;
    private final AlertEvidenceService alertEvidenceService;

    public ThreatIntelligenceService(
            ThreatIndicatorRepository indicatorRepository,
            ThreatIntelligenceDetectionRepository detectionRepository,
            AlertRepository alertRepository,
            AlertEvidenceService alertEvidenceService
    ) {
        this.indicatorRepository = indicatorRepository;
        this.detectionRepository = detectionRepository;
        this.alertRepository = alertRepository;
        this.alertEvidenceService = alertEvidenceService;
    }

    @Transactional
    public ThreatIndicatorImportResult importCsv(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw badRequest("Choose a non-empty CSV file to import.");
        }
        if (file.getSize() > MAX_FILE_BYTES) {
            throw badRequest("The CSV file must be smaller than 1 MB.");
        }

        String content;
        try {
            content = new String(file.getBytes(), StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "The uploaded CSV file could not be read.",
                    exception
            );
        }

        Map<String, ParsedIndicator> importedIndicators = parseCsv(content);
        if (importedIndicators.isEmpty()) {
            return new ThreatIndicatorImportResult(0, 0);
        }

        Set<String> importedIps = importedIndicators.keySet();
        Map<String, ThreatIndicator> existingByIp = indicatorRepository
                .findAllByIpAddressIn(importedIps)
                .stream()
                .collect(Collectors.toMap(ThreatIndicator::getIpAddress, indicator -> indicator));

        List<ThreatIndicator> indicatorsToSave = new ArrayList<>();
        int updatedCount = 0;
        for (ParsedIndicator imported : importedIndicators.values()) {
            ThreatIndicator indicator = existingByIp.get(imported.ipAddress());
            if (indicator == null) {
                indicator = new ThreatIndicator();
            } else {
                updatedCount++;
            }

            indicator.setIpAddress(imported.ipAddress());
            indicator.setThreatType(imported.threatType());
            indicator.setReputationScore(imported.reputationScore());
            indicator.setSource("CSV import");
            indicatorsToSave.add(indicator);
        }

        indicatorRepository.saveAll(indicatorsToSave);
        return new ThreatIndicatorImportResult(
                indicatorsToSave.size() - updatedCount,
                updatedCount
        );
    }

    public List<ThreatIntelligenceDetection> getRecentDetections() {
        return detectionRepository.findTop100ByOrderByDetectedAtDesc();
    }

    @Transactional
    public void evaluateEvent(LogEvent event) {
        if (event.getId() == null || event.getSourceIp() == null
                || detectionRepository.existsByEventId(event.getId())) {
            return;
        }

        String ipAddress;
        try {
            ipAddress = normalizeIpAddress(event.getSourceIp());
        } catch (ResponseStatusException exception) {
            return;
        }

        indicatorRepository.findByIpAddress(ipAddress).ifPresent(indicator -> {
            LocalDateTime detectedAt = LocalDateTime.now();
            String associatedEvent = event.getEventType() == null
                    ? "UNKNOWN"
                    : event.getEventType();

            ThreatIntelligenceDetection detection = new ThreatIntelligenceDetection();
            detection.setIpAddress(indicator.getIpAddress());
            detection.setThreatType(indicator.getThreatType());
            detection.setReputationScore(indicator.getReputationScore());
            detection.setDetectedAt(detectedAt);
            detection.setAssociatedEvent(associatedEvent);
            detection.setEventId(event.getId());
            detectionRepository.save(detection);

            Alert alert = new Alert();
            alert.setSeverity("CRITICAL");
            alert.setCreatedAt(detectedAt);
            alert.setTriggeringRule("Threat Intelligence IP Match");
            alert.setSourceIp(indicator.getIpAddress());
            alert.setUsername(event.getUsername());
            alert.setEventId(event.getId());
            alert.setDescription(
                    "Threat intelligence match: "
                            + indicator.getThreatType()
                            + " IP "
                            + indicator.getIpAddress()
                            + " (reputation "
                            + indicator.getReputationScore()
                            + "/100) observed in "
                            + associatedEvent
                            + "."
            );
            Alert savedAlert = alertRepository.save(alert);
            alertEvidenceService.linkEvidence(savedAlert, List.of(event));
        });
    }

    private Map<String, ParsedIndicator> parseCsv(String content) {
        try (BufferedReader reader = new BufferedReader(new StringReader(content))) {
            String headerLine = reader.readLine();
            while (headerLine != null && headerLine.isBlank()) {
                headerLine = reader.readLine();
            }
            if (headerLine == null) {
                throw badRequest("The CSV file is empty.");
            }

            List<String> headers = parseCsvRecord(headerLine);
            if (!headers.isEmpty() && headers.get(0).startsWith("\uFEFF")) {
                headers.set(0, headers.get(0).substring(1));
            }
            int ipIndex = findHeader(headers, "ip_address", "ipaddress");
            int typeIndex = findHeader(headers, "threat_type", "threattype");
            int scoreIndex = findHeader(headers, "reputation_score", "reputationscore");
            if (headers.size() != 3 || ipIndex < 0 || typeIndex < 0 || scoreIndex < 0) {
                throw badRequest(
                        "CSV header must contain ip_address, threat_type, and reputation_score."
                );
            }

            Map<String, ParsedIndicator> indicators = new LinkedHashMap<>();
            String line;
            int lineNumber = 1;
            int recordCount = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank()) {
                    continue;
                }
                recordCount++;
                if (recordCount > MAX_INDICATORS) {
                    throw badRequest("A single import may contain at most 5,000 IP addresses.");
                }

                List<String> fields = parseCsvRecord(line);
                if (fields.size() != headers.size()) {
                    throw badRequest("Invalid CSV column count on line " + lineNumber + ".");
                }

                String ipAddress = normalizeIpAddress(fields.get(ipIndex));
                String threatType = fields.get(typeIndex).trim();
                if (threatType.isEmpty() || threatType.length() > 100) {
                    throw badRequest("Threat type on line " + lineNumber + " must be 1-100 characters.");
                }

                int reputationScore;
                try {
                    reputationScore = Integer.parseInt(fields.get(scoreIndex).trim());
                } catch (NumberFormatException exception) {
                    throw badRequest("Reputation score on line " + lineNumber + " must be an integer.");
                }
                if (reputationScore < 0 || reputationScore > 100) {
                    throw badRequest("Reputation score on line " + lineNumber + " must be between 0 and 100.");
                }

                indicators.put(
                        ipAddress,
                        new ParsedIndicator(ipAddress, threatType, reputationScore)
                );
            }
            return indicators;
        } catch (IOException exception) {
            throw new IllegalStateException("Could not parse uploaded CSV content.", exception);
        }
    }

    private int findHeader(List<String> headers, String firstChoice, String secondChoice) {
        int index = -1;
        for (int headerIndex = 0; headerIndex < headers.size(); headerIndex++) {
            String header = headers.get(headerIndex).trim().toLowerCase(Locale.ROOT);
            if (header.equals(firstChoice) || header.equals(secondChoice)) {
                if (index >= 0) {
                    return -1;
                }
                index = headerIndex;
            }
        }
        return index;
    }

    private List<String> parseCsvRecord(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;

        for (int index = 0; index < line.length(); index++) {
            char current = line.charAt(index);
            if (current == '"') {
                if (quoted && index + 1 < line.length() && line.charAt(index + 1) == '"') {
                    field.append('"');
                    index++;
                } else {
                    quoted = !quoted;
                }
            } else if (current == ',' && !quoted) {
                fields.add(field.toString().trim());
                field.setLength(0);
            } else {
                field.append(current);
            }
        }

        if (quoted) {
            throw badRequest("The CSV contains an unterminated quoted field.");
        }
        fields.add(field.toString().trim());
        return fields;
    }

    private String normalizeIpAddress(String rawIpAddress) {
        String ipAddress = rawIpAddress == null
                ? ""
                : rawIpAddress.trim();
        if (ipAddress.isEmpty()) {
            throw badRequest("IP addresses in the CSV must not be empty.");
        }

        if (!ipAddress.contains(":")) {
            String[] octets = ipAddress.split("\\.", -1);
            if (octets.length != 4) {
                throw badRequest("Invalid IP address: " + ipAddress);
            }
            for (int index = 0; index < octets.length; index++) {
                if (!octets[index].matches("\\d{1,3}")) {
                    throw badRequest("Invalid IP address: " + ipAddress);
                }
                int value = Integer.parseInt(octets[index]);
                if (value > 255) {
                    throw badRequest("Invalid IP address: " + ipAddress);
                }
                octets[index] = Integer.toString(value);
            }
            return String.join(".", octets);
        }

        try {
            if (ipAddress.contains("%")) {
                throw badRequest("IPv6 zone identifiers are not supported.");
            }
            InetAddress address = InetAddress.getByName(ipAddress);
            if (!(address instanceof Inet6Address)) {
                throw badRequest("Invalid IPv6 address: " + ipAddress);
            }
            return address.getHostAddress().toLowerCase(Locale.ROOT);
        } catch (IOException exception) {
            throw badRequest("Invalid IPv6 address: " + ipAddress);
        }
    }

    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private record ParsedIndicator(String ipAddress, String threatType, int reputationScore) {
    }
}
