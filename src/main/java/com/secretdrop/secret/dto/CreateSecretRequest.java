package com.secretdrop.secret.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "Request body for creating a new secret")
public record CreateSecretRequest(
        @NotBlank
        @Size(max = 65536)
        @Schema(description = "Secret content to store", example = "database-password-123")
        String content,

        @Min(5)
        @Max(10080)
        @Schema(description = "Minutes until expiry (5–10080)", example = "60")
        Integer expiryMinutes,

        @Min(1)
        @Max(10)
        @Schema(description = "Maximum number of times the secret can be viewed", example = "1")
        Integer maxViews,

        @Size(min = 4, max = 128)
        @Schema(description = "Optional passphrase required to reveal the secret")
        String passphrase) {}