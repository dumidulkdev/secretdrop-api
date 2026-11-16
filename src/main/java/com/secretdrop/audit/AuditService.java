package com.secretdrop.audit;

import com.secretdrop.crypto.CryptoService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class AuditService {

    private final AuditLogRepository repository;
    private final CryptoService cryptoService;

    public AuditService(AuditLogRepository repository, CryptoService cryptoService) {
        this.repository = repository;
        this.cryptoService = cryptoService;
    }

    @Transactional
    public void record(UUID secretId, AuditEventType eventType) {
        AuditLogEntity entry = new AuditLogEntity();
        entry.setSecretIdHash(cryptoService.hashToken(secretId.toString()));
        entry.setEventType(eventType);
        entry.setOccurredAt(Instant.now());
        repository.save(entry);
    }
}