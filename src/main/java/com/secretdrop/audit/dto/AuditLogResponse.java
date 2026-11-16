package com.secretdrop.audit.dto;

import com.secretdrop.audit.AuditEventType;

import java.time.Instant;

public record AuditLogResponse(
        String secretIdHash,
        AuditEventType eventType,
        Instant occurredAt) {}