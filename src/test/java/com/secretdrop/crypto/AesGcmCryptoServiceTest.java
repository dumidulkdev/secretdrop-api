package com.secretdrop.crypto;

import com.secretdrop.config.SecretDropProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AesGcmCryptoServiceTest {

    private AesGcmCryptoService cryptoService;

    @BeforeEach
    void setUp() {
        SecretDropProperties props = new SecretDropProperties(
                new SecretDropProperties.Crypto("test-master-key-at-least-32-characters-long"),
                new SecretDropProperties.Secrets(60, 5, 10080, 1, 10, 65536, 24, 24, 5),
                new SecretDropProperties.RateLimit(
                        new SecretDropProperties.EndpointLimit(30, 30),
                        new SecretDropProperties.EndpointLimit(60, 60)));
        cryptoService = new AesGcmCryptoService(props);
    }

    @Test
    void encryptDecryptRoundTrip() {
        byte[] key = cryptoService.masterKey();
        byte[] plaintext = "hello-secret".getBytes(StandardCharsets.UTF_8);

        EncryptedPayload encrypted = cryptoService.encrypt(plaintext, key);
        byte[] decrypted = cryptoService.decrypt(encrypted, key);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void tamperedCiphertextFailsDecryption() {
        byte[] key = cryptoService.masterKey();
        EncryptedPayload encrypted = cryptoService.encrypt("data".getBytes(StandardCharsets.UTF_8), key);
        byte[] tampered = encrypted.ciphertext().clone();
        tampered[0] ^= 0x01;

        EncryptedPayload bad = new EncryptedPayload(tampered, encrypted.iv());
        assertThatThrownBy(() -> cryptoService.decrypt(bad, key))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    void wrongPassphraseKeyFailsDecryption() {
        byte[] master = cryptoService.masterKey();
        byte[] salt = cryptoService.generateSalt(16);
        char[] good = "correct horse".toCharArray();
        char[] wrong = "wrong horse".toCharArray();

        byte[] goodKey = cryptoService.deriveContentKey(master, salt, good);
        EncryptedPayload encrypted = cryptoService.encrypt("payload".getBytes(StandardCharsets.UTF_8), goodKey);
        byte[] badKey = cryptoService.deriveContentKey(master, salt, wrong);

        assertThatThrownBy(() -> cryptoService.decrypt(encrypted, badKey))
                .isInstanceOf(CryptoException.class);

        Arrays.fill(good, '\0');
        Arrays.fill(wrong, '\0');
    }

    @Test
    void tokenHashVerification() {
        String token = cryptoService.generateUrlSafeToken(24);
        String hash = cryptoService.hashToken(token);
        assertThat(cryptoService.verifyToken(token, hash)).isTrue();
        assertThat(cryptoService.verifyToken(token + "x", hash)).isFalse();
    }
}