package com.secretdrop.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "secretdrop")
public record SecretDropProperties(
        Crypto crypto,
        Secrets secrets,
        RateLimit rateLimit) {

    public record Crypto(String masterKey) {}

    public record Secrets(
            int defaultExpiryMinutes,
            int minExpiryMinutes,
            int maxExpiryMinutes,
            int defaultMaxViews,
            int maxMaxViews,
            int maxContentBytes,
            int accessTokenBytes,
            int deleteTokenBytes,
            int maxPassphraseFailures) {}

    public record RateLimit(EndpointLimit reveal, EndpointLimit status) {}

    public record EndpointLimit(long capacity, long refillPerMinute) {}
}