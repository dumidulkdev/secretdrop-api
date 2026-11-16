package com.secretdrop.secret;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SecretRepository extends JpaRepository<SecretEntity, UUID> {

    Optional<SecretEntity> findByAccessTokenHash(String accessTokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT s FROM SecretEntity s WHERE s.accessTokenHash = :hash")
    Optional<SecretEntity> findByAccessTokenHashForUpdate(@Param("hash") String hash);

    @Query("SELECT s FROM SecretEntity s WHERE s.expiresAt < :now")
    List<SecretEntity> findExpired(@Param("now") Instant now);
}