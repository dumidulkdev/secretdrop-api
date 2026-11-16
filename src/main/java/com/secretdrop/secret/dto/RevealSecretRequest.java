package com.secretdrop.secret.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Optional passphrase for protected secrets (POST reveal)")
public record RevealSecretRequest(
        @Schema(description = "Passphrase when the secret was created with one")
        String passphrase) {}