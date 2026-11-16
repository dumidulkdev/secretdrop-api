package com.secretdrop.crypto;

public interface CryptoService {

    EncryptedPayload encrypt(byte[] plaintext, byte[] keyMaterial);

    byte[] decrypt(EncryptedPayload payload, byte[] keyMaterial);

    byte[] deriveContentKey(byte[] masterKey, byte[] passphraseSalt, char[] passphrase);

    byte[] generateSalt(int length);

    String generateUrlSafeToken(int numBytes);

    String hashToken(String rawToken);

    boolean verifyToken(String rawToken, String storedHash);
}