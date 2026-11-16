package com.secretdrop.crypto;

import com.secretdrop.config.SecretDropProperties;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

@Service
public class AesGcmCryptoService implements CryptoService {

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;
    private static final int AES_KEY_BYTES = 32;
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    private final SecureRandom secureRandom;
    private final byte[] masterKey;

    public AesGcmCryptoService(SecretDropProperties properties) {
        this.secureRandom = new SecureRandom();
        String configured = properties.crypto().masterKey();
        if (configured == null || configured.isBlank()) {
            throw new IllegalStateException("secretdrop.crypto.master-key must be configured");
        }
        this.masterKey = digestToKey(configured.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public EncryptedPayload encrypt(byte[] plaintext, byte[] keyMaterial) {
        byte[] iv = new byte[IV_BYTES];
        secureRandom.nextBytes(iv);
        byte[] key = normalizeKey(keyMaterial);
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return new EncryptedPayload(ciphertext, iv);
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    @Override
    public byte[] decrypt(EncryptedPayload payload, byte[] keyMaterial) {
        byte[] key = normalizeKey(keyMaterial);
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, payload.iv()));
            return cipher.doFinal(payload.ciphertext());
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    @Override
    public byte[] deriveContentKey(byte[] masterKeyInput, byte[] passphraseSalt, char[] passphrase) {
        if (passphrase == null || passphrase.length == 0) {
            return normalizeKey(masterKeyInput);
        }
        try {
            KeySpec spec = new PBEKeySpec(passphrase, combineMasterAndSalt(masterKeyInput, passphraseSalt), PBKDF2_ITERATIONS, AES_KEY_BYTES * 8);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new CryptoException("Key derivation failed", e);
        }
    }

    @Override
    public byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        secureRandom.nextBytes(salt);
        return salt;
    }

    @Override
    public String generateUrlSafeToken(int numBytes) {
        byte[] bytes = new byte[numBytes];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new CryptoException("Token hashing failed", e);
        }
    }

    @Override
    public boolean verifyToken(String rawToken, String storedHash) {
        return MessageDigest.isEqual(
                hashToken(rawToken).getBytes(StandardCharsets.UTF_8),
                storedHash.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] masterKey() {
        return masterKey.clone();
    }

    private static byte[] combineMasterAndSalt(byte[] master, byte[] salt) {
        byte[] combined = new byte[master.length + salt.length];
        System.arraycopy(master, 0, combined, 0, master.length);
        System.arraycopy(salt, 0, combined, master.length, salt.length);
        return combined;
    }

    private static byte[] normalizeKey(byte[] keyMaterial) {
        if (keyMaterial.length == AES_KEY_BYTES) {
            return keyMaterial.clone();
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(keyMaterial);
        } catch (Exception e) {
            throw new CryptoException("Key normalization failed", e);
        }
    }

    private static byte[] digestToKey(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (Exception e) {
            throw new CryptoException("Master key initialization failed", e);
        }
    }
}