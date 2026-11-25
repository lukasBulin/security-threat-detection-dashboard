package com.lukas.security_dashboard.repository;

import com.lukas.security_dashboard.model.ThreatIndicator;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface ThreatIndicatorRepository extends JpaRepository<ThreatIndicator, Long> {
    Optional<ThreatIndicator> findByIpAddress(String ipAddress);

    List<ThreatIndicator> findAllByIpAddressIn(Collection<String> ipAddresses);
}
