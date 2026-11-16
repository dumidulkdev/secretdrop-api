package com.secretdrop.crypto;

public record EncryptedPayload(byte[] ciphertext, byte[] iv) {}