package com.lukas.security_dashboard.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

@Entity
@Table(name = "threat_indicator")
public class ThreatIndicator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 45)
    private String ipAddress;

    @Column(nullable = false, length = 100)
    private String threatType;

    @Column(nullable = false)
    private int reputationScore;

    @Column(nullable = false, length = 80)
    private String source;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

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

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    @PrePersist
    @PreUpdate
    protected void updateTimestamp() {
        updatedAt = LocalDateTime.now();
    }
}
