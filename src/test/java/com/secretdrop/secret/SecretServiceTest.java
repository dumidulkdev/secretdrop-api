package com.secretdrop.secret;

import com.secretdrop.audit.AuditLogRepository;
import com.secretdrop.config.SecretDropProperties;
import com.secretdrop.crypto.AesGcmCryptoService;
import com.secretdrop.secret.dto.CreateSecretRequest;
import com.secretdrop.secret.dto.CreateSecretResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("local")
class SecretServiceTest {

    @Autowired
    private SecretService secretService;

    @Autowired
    private SecretRepository secretRepository;

    @Autowired
    private AesGcmCryptoService aesGcmCryptoService;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @BeforeEach
    void cleanDb() {
        secretRepository.deleteAll();
        auditLogRepository.deleteAll();
    }

    @Test
    void burnAfterMaxViews() {
        CreateSecretResponse created = secretService.create(
                new CreateSecretRequest("burn-me", 60, 1, null));

        var reveal = secretService.reveal(created.accessToken(), null);
        assertThat(reveal.content()).isEqualTo("burn-me");
        assertThat(reveal.remainingViews()).isZero();

        assertThatThrownBy(() -> secretService.reveal(created.accessToken(), null))
                .isInstanceOf(SecretNotFoundException.class);
    }

    @Test
    void expiredSecretIsNotFound() {
        CreateSecretResponse created = secretService.create(
                new CreateSecretRequest("short-lived", 5, 5, null));

        String hash = aesGcmCryptoService.hashToken(created.accessToken());
        SecretEntity entity = secretRepository.findByAccessTokenHash(hash).orElseThrow();
        entity.setExpiresAt(Instant.now().minus(1, ChronoUnit.MINUTES));
        secretRepository.save(entity);

        assertThatThrownBy(() -> secretService.reveal(created.accessToken(), null))
                .isInstanceOf(SecretNotFoundException.class);
    }

    @Test
    void wrongPassphraseEventuallyBurnsSecret() {
        CreateSecretResponse created = secretService.create(
                new CreateSecretRequest("protected", 60, 5, "secret-pass"));

        for (int i = 0; i < 4; i++) {
            assertThatThrownBy(() -> secretService.reveal(created.accessToken(), "wrong"))
                    .isInstanceOf(SecretNotFoundException.class);
        }

        assertThatThrownBy(() -> secretService.reveal(created.accessToken(), "wrong"))
                .isInstanceOf(SecretNotFoundException.class);

        assertThatThrownBy(() -> secretService.reveal(created.accessToken(), "secret-pass"))
                .isInstanceOf(SecretNotFoundException.class);
    }
}