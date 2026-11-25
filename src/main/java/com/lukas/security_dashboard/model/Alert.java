package com.lukas.security_dashboard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String severity;
    private String description;
    private LocalDateTime createdAt;
    private String triggeringRule;
    private String sourceIp;
    private String username;
    private Long eventId;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public String getTriggeringRule() {
        return triggeringRule;
    }

    public void setTriggeringRule(String triggeringRule) {
        this.triggeringRule = triggeringRule;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Long getEventId() {
        return eventId;
    }

    public void setEventId(Long eventId) {
        this.eventId = eventId;
    }

    @PrePersist
    protected void setCreatedAtIfMissing() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}