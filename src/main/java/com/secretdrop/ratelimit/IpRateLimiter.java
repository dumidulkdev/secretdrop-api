package com.secretdrop.ratelimit;

import com.secretdrop.config.SecretDropProperties;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class IpRateLimiter {

    public enum BucketType {
        REVEAL,
        STATUS
    }

    private final SecretDropProperties properties;
    private final Map<String, Bucket> revealBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> statusBuckets = new ConcurrentHashMap<>();

    public IpRateLimiter(SecretDropProperties properties) {
        this.properties = properties;
    }

    public void check(String clientIp, BucketType type) {
        Bucket bucket = resolveBucket(clientIp, type);
        if (!bucket.tryConsume(1)) {
            long retryAfter = Math.max(1, 60 / Math.max(1, refillPerMinute(type)));
            throw new RateLimitExceededException(retryAfter);
        }
    }

    private Bucket resolveBucket(String clientIp, BucketType type) {
        Map<String, Bucket> buckets = type == BucketType.REVEAL ? revealBuckets : statusBuckets;
        return buckets.computeIfAbsent(clientIp, key -> newBucket(type));
    }

    private Bucket newBucket(BucketType type) {
        long capacity = capacity(type);
        long refill = refillPerMinute(type);
        Bandwidth limit = Bandwidth.builder()
                .capacity(capacity)
                .refillGreedy(refill, Duration.ofMinutes(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    private long capacity(BucketType type) {
        return type == BucketType.REVEAL
                ? properties.rateLimit().reveal().capacity()
                : properties.rateLimit().status().capacity();
    }

    private long refillPerMinute(BucketType type) {
        return type == BucketType.REVEAL
                ? properties.rateLimit().reveal().refillPerMinute()
                : properties.rateLimit().status().refillPerMinute();
    }
}