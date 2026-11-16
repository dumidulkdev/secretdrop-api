package com.secretdrop.secret;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class SecretCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(SecretCleanupJob.class);

    private final SecretService secretService;

    public SecretCleanupJob(SecretService secretService) {
        this.secretService = secretService;
    }

    @Scheduled(fixedDelayString = "PT5M")
    public void purgeExpiredSecrets() {
        int removed = secretService.purgeExpired(Instant.now());
        if (removed > 0) {
            log.info("Purged {} expired secrets", removed);
        }
    }
}