package com.lukas.security_dashboard.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "threat_intelligence_detection",
        indexes = @Index(name = "idx_threat_detection_detected_at", columnList = "detected_at")
)
public class ThreatIntelligenceDetection {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 45)
    private String ipAddress;

    @Column(nullable = false, length = 100)
    private String threatType;

    @Column(nullable = false)
    private int reputationScore;

    @Column(nullable = false)
    private LocalDateTime detectedAt;

    @Column(nullable = false, length = 64)
    private String associatedEvent;

    @Column(nullable = false, unique = true)
    private Long eventId;

    public Long getId() {
        return id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getThreatType() {
        return threatType;
    }

    public void setThreatType(String threatType) {
        this.threatType = threatType;
    }

    public int getReputationScore() {
        return reputationScore;
    }

    public void setReputationScore(int reputationScore) {
        this.reputationScore = reputationScore;
    }

    public LocalDateTime getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(LocalDateTime detectedAt) {
        this.detectedAt = detectedAt;
    }

    public String getAssociatedEvent() {
        return associatedEvent;
    }

    public void setAssociatedEvent(String associatedEvent) {
        this.associatedEvent = associatedEvent;
    }

    public Long getEventId() {
        return eventId;
    }

    public void setEventId(Long eventId) {
        this.eventId = eventId;
    }
}
