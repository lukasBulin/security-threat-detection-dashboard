package com.lukas.security_dashboard.service;

import com.lukas.security_dashboard.model.LogEvent;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class DataGeneratorService {

    private static final int MALICIOUS_PERCENT = 10;
    private static final int FAILED_LOGINS_PER_SCENARIO = 5;
    private static final int COMPROMISE_SCENARIO_SIZE = FAILED_LOGINS_PER_SCENARIO + 1;
    private static final long ATTACK_IP_ADDRESS_COUNT = 2L * 256 * 254;

    private final LogEventService logEventService;
    private final AtomicLong attackIpSequence = new AtomicLong(
            ThreadLocalRandom.current().nextLong(ATTACK_IP_ADDRESS_COUNT)
    );

    public DataGeneratorService(LogEventService logEventService) {
        this.logEventService = logEventService;
    }

    @Transactional
    public void generateLogs(int count) {
        Random random = new Random();
        int maliciousCount = count / (100 / MALICIOUS_PERCENT);
        int legitimateCount = count - maliciousCount;
        List<List<LogEvent>> activityGroups = new ArrayList<>();

        for (int i = 0; i < legitimateCount; i++) {
            activityGroups.add(List.of(generateLegitimateEvent(random)));
        }

        int remainingMaliciousEvents = maliciousCount;
        while (remainingMaliciousEvents >= FAILED_LOGINS_PER_SCENARIO
                + COMPROMISE_SCENARIO_SIZE) {
            activityGroups.add(generateBruteForceScenario(random));
            activityGroups.add(generateCompromiseScenario(random));
            remainingMaliciousEvents -= FAILED_LOGINS_PER_SCENARIO
                    + COMPROMISE_SCENARIO_SIZE;
        }

        if (remainingMaliciousEvents >= COMPROMISE_SCENARIO_SIZE) {
            activityGroups.add(generateCompromiseScenario(random));
            remainingMaliciousEvents -= COMPROMISE_SCENARIO_SIZE;
        }
        if (remainingMaliciousEvents >= FAILED_LOGINS_PER_SCENARIO) {
            activityGroups.add(generateBruteForceScenario(random));
            remainingMaliciousEvents -= FAILED_LOGINS_PER_SCENARIO;
        }
        if (remainingMaliciousEvents > 0) {
            activityGroups.add(generateFailedLoginAttempts(remainingMaliciousEvents, random));
        }

        Collections.shuffle(activityGroups, random);
        for (List<LogEvent> group : activityGroups) {
            for (LogEvent event : group) {
                logEventService.save(event);
            }
        }
    }

    private LogEvent generateLegitimateEvent(Random random) {
        int eventTypeChoice = random.nextInt(100);
        String eventType = eventTypeChoice < 82
                ? "LOGIN_SUCCESS"
                : eventTypeChoice < 97
                        ? "PASSWORD_RESET"
                        : "ACCOUNT_LOCKED";

        return createEvent(
                "10.0.0." + (random.nextInt(254) + 1),
                "user" + random.nextInt(500),
                eventType
        );
    }

    private List<LogEvent> generateBruteForceScenario(Random random) {
        return generateFailedLoginAttempts(FAILED_LOGINS_PER_SCENARIO, random);
    }

    private List<LogEvent> generateCompromiseScenario(Random random) {
        List<LogEvent> events = generateFailedLoginAttempts(
                FAILED_LOGINS_PER_SCENARIO,
                random
        );
        LogEvent successfulLogin = createEvent(
                events.get(0).getSourceIp(),
                events.get(0).getUsername(),
                "LOGIN_SUCCESS"
        );
        events.add(successfulLogin);
        return events;
    }

    private List<LogEvent> generateFailedLoginAttempts(int count, Random random) {
        String sourceIp = nextAttackIp();
        String username = "user" + random.nextInt(500);
        List<LogEvent> events = new ArrayList<>(count);

        for (int i = 0; i < count; i++) {
            events.add(createEvent(sourceIp, username, "LOGIN_FAILED"));
        }
        return events;
    }

    private String nextAttackIp() {
        long sequence = attackIpSequence.getAndIncrement() % ATTACK_IP_ADDRESS_COUNT;
        int secondOctet = 18 + (int) (sequence / (256L * 254));
        long addressInBlock = sequence % (256L * 254);
        int thirdOctet = (int) (addressInBlock / 254);
        int fourthOctet = (int) (addressInBlock % 254) + 1;
        return "198." + secondOctet + "." + thirdOctet + "." + fourthOctet;
    }

    private LogEvent createEvent(String sourceIp, String username, String eventType) {
        LogEvent event = new LogEvent();
        event.setTimestamp(LocalDateTime.now());
        event.setSourceIp(sourceIp);
        event.setUsername(username);
        event.setEventType(eventType);
        return event;
    }
}
