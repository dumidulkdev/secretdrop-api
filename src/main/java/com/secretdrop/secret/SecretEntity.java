package com.secretdrop.secret;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "secrets")
public class SecretEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 64)
    private String accessTokenHash;

    @Column(nullable = false, length = 64)
    private String deleteTokenHash;

    @Column(nullable = false)
    private byte[] ciphertext;

    @Column(nullable = false, length = 16)
    private byte[] iv;

    @Column
    private byte[] passphraseSalt;

    @Column(length = 72)
    private String passphraseHash;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private int maxViews;

    @Column(nullable = false)
    private int viewCount;

    @Column(nullable = false)
    private int passphraseFailureCount;

    @Column(nullable = false)
    private Instant createdAt;

    @Version
    private long version;

    public UUID getId() {
        return id;
    }

    public String getAccessTokenHash() {
        return accessTokenHash;
    }

    public void setAccessTokenHash(String accessTokenHash) {
        this.accessTokenHash = accessTokenHash;
    }

    public String getDeleteTokenHash() {
        return deleteTokenHash;
    }

    public void setDeleteTokenHash(String deleteTokenHash) {
        this.deleteTokenHash = deleteTokenHash;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(byte[] ciphertext) {
        this.ciphertext = ciphertext;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getPassphraseSalt() {
        return passphraseSalt;
    }

    public void setPassphraseSalt(byte[] passphraseSalt) {
        this.passphraseSalt = passphraseSalt;
    }

    public String getPassphraseHash() {
        return passphraseHash;
    }

    public void setPassphraseHash(String passphraseHash) {
        this.passphraseHash = passphraseHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public int getMaxViews() {
        return maxViews;
    }

    public void setMaxViews(int maxViews) {
        this.maxViews = maxViews;
    }

    public int getViewCount() {
        return viewCount;
    }

    public void setViewCount(int viewCount) {
        this.viewCount = viewCount;
    }

    public int getPassphraseFailureCount() {
        return passphraseFailureCount;
    }

    public void setPassphraseFailureCount(int passphraseFailureCount) {
        this.passphraseFailureCount = passphraseFailureCount;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public long getVersion() {
        return version;
    }

    public boolean isPassphraseProtected() {
        return passphraseHash != null;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public int remainingViews() {
        return Math.max(0, maxViews - viewCount);
    }
}