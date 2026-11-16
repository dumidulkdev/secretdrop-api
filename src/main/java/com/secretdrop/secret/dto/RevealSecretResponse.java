package com.secretdrop.secret.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Decrypted secret content")
public record RevealSecretResponse(
        @Schema(description = "Plaintext secret content")
        String content,
        @Schema(description = "Views remaining after this reveal")
        int remainingViews) {}