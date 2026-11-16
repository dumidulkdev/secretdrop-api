package com.secretdrop.secret.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(description = "Response after creating a secret")
public record CreateSecretResponse(
        @Schema(description = "URL-safe token used to reveal or check status")
        String accessToken,
        @Schema(description = "Token required to delete the secret early")
        String deleteToken,
        @Schema(description = "When the secret expires")
        Instant expiresAt,
        @Schema(description = "Maximum allowed views")
        int maxViews) {}