package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.LogEvent;
import com.lukas.security_dashboard.repository.LogEventRepository;
import org.springframework.stereotype.Service;

import javax.xml.crypto.Data;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Random;

@Service
public class DataGeneratorService {

    private final LogEventRepository repository;

    public DataGeneratorService(LogEventRepository repository)
    {
        this.repository = repository;
    }

    public void generateLogs(int count) {

        Random random = new Random();

        String[] eventTypes = {
                "LOGIN_SUCCESS",
                "LOGIN_FAILED",
                "PASSWORD_RESET",
                "ACCOUNT_LOCKED"
        };

        for (int i = 0; i < count; i++)
        {
            LogEvent log = new LogEvent();

            log.setTimestamp(LocalDateTime.now());

            log.setSourceIp(
                    "192.168.1." + random.nextInt(255)
            );

            log.setUsername(
                    "user" + random.nextInt(100)
            );

            log.setEventType(
                    eventTypes[random.nextInt(eventTypes.length)]
            );

            repository.save(log);
        }
    }
}
