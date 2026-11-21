package com.lukas.security_dashboard.repository;

import com.lukas.security_dashboard.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AlertRepository extends JpaRepository<Alert, Long> {

}