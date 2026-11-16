package com.secretdrop.secret.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(description = "Non-sensitive status of an active secret")
public record SecretStatusResponse(
        @Schema(description = "Whether the secret can still be revealed")
        boolean active,
        @Schema(description = "Views remaining")
        int remainingViews,
        @Schema(description = "Expiration time")
        Instant expiresAt,
        @Schema(description = "True if a passphrase is required to reveal")
        boolean passphraseRequired) {}