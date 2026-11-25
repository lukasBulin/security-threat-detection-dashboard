package com.lukas.security_dashboard.model;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(
        name = "alert_evidence",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_alert_evidence_alert_log",
                columnNames = {"alert_id", "log_event_id"}
        )
)
public class AlertEvidence {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "alert_id", nullable = false)
    private Alert alert;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "log_event_id", nullable = false)
    private LogEvent logEvent;

    public AlertEvidence(Alert alert, LogEvent logEvent) {
        this.alert = alert;
        this.logEvent = logEvent;
    }

    protected AlertEvidence() {
    }
}
