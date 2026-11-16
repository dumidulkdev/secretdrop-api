package com.secretdrop.secret;

import com.secretdrop.audit.AuditEventType;
import com.secretdrop.audit.AuditService;
import com.secretdrop.config.SecretDropProperties;
import com.secretdrop.crypto.AesGcmCryptoService;
import com.secretdrop.crypto.CryptoService;
import com.secretdrop.crypto.EncryptedPayload;
import com.secretdrop.secret.dto.CreateSecretRequest;
import com.secretdrop.secret.dto.CreateSecretResponse;
import com.secretdrop.secret.dto.RevealSecretResponse;
import com.secretdrop.secret.dto.SecretStatusResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;

@Service
public class SecretService {

    private final SecretRepository secretRepository;
    private final CryptoService cryptoService;
    private final AesGcmCryptoService aesGcmCryptoService;
    private final SecretDropProperties properties;
    private final AuditService auditService;
    private final PasswordEncoder passwordEncoder;

    public SecretService(
            SecretRepository secretRepository,
            CryptoService cryptoService,
            AesGcmCryptoService aesGcmCryptoService,
            SecretDropProperties properties,
            AuditService auditService,
            PasswordEncoder passwordEncoder) {
        this.secretRepository = secretRepository;
        this.cryptoService = cryptoService;
        this.aesGcmCryptoService = aesGcmCryptoService;
        this.properties = properties;
        this.auditService = auditService;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public CreateSecretResponse create(CreateSecretRequest request) {
        validateContentSize(request.content());

        int expiryMinutes = request.expiryMinutes() != null
                ? request.expiryMinutes()
                : properties.secrets().defaultExpiryMinutes();
        validateExpiry(expiryMinutes);

        int maxViews = request.maxViews() != null
                ? request.maxViews()
                : properties.secrets().defaultMaxViews();
        if (maxViews > properties.secrets().maxMaxViews()) {
            throw new IllegalArgumentException("maxViews exceeds allowed maximum");
        }

        String accessToken = cryptoService.generateUrlSafeToken(properties.secrets().accessTokenBytes());
        String deleteToken = cryptoService.generateUrlSafeToken(properties.secrets().deleteTokenBytes());

        byte[] masterKey = aesGcmCryptoService.masterKey();
        byte[] passphraseSalt = null;
        char[] passphraseChars = null;
        byte[] contentKey;
        String passphraseHash = null;

        if (request.passphrase() != null && !request.passphrase().isBlank()) {
            passphraseSalt = cryptoService.generateSalt(16);
            passphraseChars = request.passphrase().toCharArray();
            contentKey = cryptoService.deriveContentKey(masterKey, passphraseSalt, passphraseChars);
            passphraseHash = passwordEncoder.encode(request.passphrase());
        } else {
            contentKey = masterKey.clone();
        }

        try {
            EncryptedPayload encrypted = cryptoService.encrypt(
                    request.content().getBytes(StandardCharsets.UTF_8), contentKey);

            SecretEntity entity = new SecretEntity();
            entity.setAccessTokenHash(cryptoService.hashToken(accessToken));
            entity.setDeleteTokenHash(cryptoService.hashToken(deleteToken));
            entity.setCiphertext(encrypted.ciphertext());
            entity.setIv(encrypted.iv());
            entity.setPassphraseSalt(passphraseSalt);
            entity.setPassphraseHash(passphraseHash);
            entity.setExpiresAt(Instant.now().plusSeconds(expiryMinutes * 60L));
            entity.setMaxViews(maxViews);
            entity.setViewCount(0);
            entity.setPassphraseFailureCount(0);
            entity.setCreatedAt(Instant.now());

            SecretEntity saved = secretRepository.save(entity);
            auditService.record(saved.getId(), AuditEventType.CREATED);

            return new CreateSecretResponse(accessToken, deleteToken, entity.getExpiresAt(), maxViews);
        } finally {
            if (passphraseChars != null) {
                Arrays.fill(passphraseChars, '\0');
            }
            Arrays.fill(contentKey, (byte) 0);
        }
    }

    @Transactional(noRollbackFor = SecretNotFoundException.class)
    public RevealSecretResponse reveal(String accessToken, String passphrase) {
        SecretEntity secret = loadActiveSecretForUpdate(accessToken);

        if (secret.isPassphraseProtected()) {
            validatePassphrase(secret, passphrase);
        }

        String content = decryptContent(secret, passphrase);
        secret.setViewCount(secret.getViewCount() + 1);
        secretRepository.save(secret);
        auditService.record(secret.getId(), AuditEventType.VIEWED);

        int remaining = secret.remainingViews();
        if (secret.getViewCount() >= secret.getMaxViews()) {
            secretRepository.delete(secret);
            auditService.record(secret.getId(), AuditEventType.BURNED);
            remaining = 0;
        }

        return new RevealSecretResponse(content, remaining);
    }

    @Transactional(readOnly = true)
    public SecretStatusResponse status(String accessToken) {
        SecretEntity secret = loadActiveSecretReadOnly(accessToken);
        return new SecretStatusResponse(
                true,
                secret.remainingViews(),
                secret.getExpiresAt(),
                secret.isPassphraseProtected());
    }

    @Transactional
    public void delete(String accessToken, String deleteToken) {
        SecretEntity secret = secretRepository
                .findByAccessTokenHash(cryptoService.hashToken(accessToken))
                .orElseThrow(SecretNotFoundException::new);

        if (!cryptoService.verifyToken(deleteToken, secret.getDeleteTokenHash())) {
            throw new SecretNotFoundException();
        }

        secretRepository.delete(secret);
        auditService.record(secret.getId(), AuditEventType.DELETED);
    }

    @Transactional
    public int purgeExpired(Instant now) {
        var expired = secretRepository.findExpired(now);
        for (SecretEntity secret : expired) {
            secretRepository.delete(secret);
            auditService.record(secret.getId(), AuditEventType.EXPIRED);
        }
        return expired.size();
    }

    private SecretEntity loadActiveSecretForUpdate(String accessToken) {
        SecretEntity secret = secretRepository
                .findByAccessTokenHashForUpdate(cryptoService.hashToken(accessToken))
                .orElseThrow(SecretNotFoundException::new);
        ensureActive(secret);
        return secret;
    }

    private SecretEntity loadActiveSecretReadOnly(String accessToken) {
        SecretEntity secret = secretRepository
                .findByAccessTokenHash(cryptoService.hashToken(accessToken))
                .orElseThrow(SecretNotFoundException::new);
        ensureActive(secret);
        return secret;
    }

    private void ensureActive(SecretEntity secret) {
        Instant now = Instant.now();
        if (secret.isExpired(now) || secret.remainingViews() == 0) {
            throw new SecretNotFoundException();
        }
    }

    private void validatePassphrase(SecretEntity secret, String passphrase) {
        if (passphrase == null || passphrase.isBlank()) {
            recordPassphraseFailure(secret);
            throw new SecretNotFoundException();
        }
        if (!passwordEncoder.matches(passphrase, secret.getPassphraseHash())) {
            recordPassphraseFailure(secret);
            throw new SecretNotFoundException();
        }
    }

    private void recordPassphraseFailure(SecretEntity secret) {
        secret.setPassphraseFailureCount(secret.getPassphraseFailureCount() + 1);
        auditService.record(secret.getId(), AuditEventType.FAILED_PASSPHRASE);
        if (secret.getPassphraseFailureCount() >= properties.secrets().maxPassphraseFailures()) {
            secretRepository.delete(secret);
            auditService.record(secret.getId(), AuditEventType.BURNED);
        } else {
            secretRepository.save(secret);
        }
    }

    private String decryptContent(SecretEntity secret, String passphrase) {
        byte[] masterKey = aesGcmCryptoService.masterKey();
        char[] passphraseChars = passphrase != null ? passphrase.toCharArray() : new char[0];
        byte[] contentKey = secret.isPassphraseProtected()
                ? cryptoService.deriveContentKey(masterKey, secret.getPassphraseSalt(), passphraseChars)
                : masterKey.clone();
        try {
            EncryptedPayload payload = new EncryptedPayload(secret.getCiphertext(), secret.getIv());
            byte[] plaintext = cryptoService.decrypt(payload, contentKey);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (RuntimeException ex) {
            throw new SecretNotFoundException();
        } finally {
            if (passphrase != null) {
                Arrays.fill(passphraseChars, '\0');
            }
            Arrays.fill(contentKey, (byte) 0);
        }
    }

    private void validateContentSize(String content) {
        int bytes = content.getBytes(StandardCharsets.UTF_8).length;
        if (bytes > properties.secrets().maxContentBytes()) {
            throw new IllegalArgumentException("Content exceeds maximum size");
        }
    }

    private void validateExpiry(int expiryMinutes) {
        if (expiryMinutes < properties.secrets().minExpiryMinutes()
                || expiryMinutes > properties.secrets().maxExpiryMinutes()) {
            throw new IllegalArgumentException("expiryMinutes out of allowed range");
        }
    }
}