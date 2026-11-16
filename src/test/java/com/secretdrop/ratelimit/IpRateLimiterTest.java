package com.secretdrop.ratelimit;

import com.secretdrop.config.SecretDropProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IpRateLimiterTest {

    @Test
    void blocksWhenBucketIsExhausted() {
        SecretDropProperties props = new SecretDropProperties(
                new SecretDropProperties.Crypto("key"),
                new SecretDropProperties.Secrets(60, 5, 10080, 1, 10, 65536, 24, 24, 5),
                new SecretDropProperties.RateLimit(
                        new SecretDropProperties.EndpointLimit(2, 1),
                        new SecretDropProperties.EndpointLimit(2, 1)));
        IpRateLimiter limiter = new IpRateLimiter(props);

        limiter.check("203.0.113.1", IpRateLimiter.BucketType.REVEAL);
        limiter.check("203.0.113.1", IpRateLimiter.BucketType.REVEAL);

        assertThatThrownBy(() -> limiter.check("203.0.113.1", IpRateLimiter.BucketType.REVEAL))
                .isInstanceOf(RateLimitExceededException.class)
                .satisfies(ex -> assertThatCode(() -> ((RateLimitExceededException) ex).retryAfterSeconds())
                        .doesNotThrowAnyException());
    }
}