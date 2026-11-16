package com.secretdrop.secret;

import com.secretdrop.common.api.ApiResponse;
import com.secretdrop.common.web.ClientIpResolver;
import com.secretdrop.ratelimit.IpRateLimiter;
import com.secretdrop.secret.dto.CreateSecretRequest;
import com.secretdrop.secret.dto.CreateSecretResponse;
import com.secretdrop.secret.dto.RevealSecretRequest;
import com.secretdrop.secret.dto.RevealSecretResponse;
import com.secretdrop.secret.dto.SecretStatusResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/secrets")
@Tag(name = "Secrets", description = "Create, reveal, and manage self-destructing secrets")
public class SecretController {

    private static final String DELETE_TOKEN_HEADER = "X-Delete-Token";

    private final SecretService secretService;
    private final IpRateLimiter rateLimiter;
    private final ClientIpResolver clientIpResolver;

    public SecretController(SecretService secretService, IpRateLimiter rateLimiter, ClientIpResolver clientIpResolver) {
        this.secretService = secretService;
        this.rateLimiter = rateLimiter;
        this.clientIpResolver = clientIpResolver;
    }

    @PostMapping
    @Operation(summary = "Create a secret", description = "Stores encrypted content and returns access and delete tokens.")
    public ResponseEntity<ApiResponse<CreateSecretResponse>> create(@Valid @RequestBody CreateSecretRequest request) {
        CreateSecretResponse created = secretService.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.of(created));
    }

    @GetMapping("/{token}/reveal")
    @Operation(summary = "Reveal a secret (GET)", description = "Decrypts content using an optional passphrase query parameter.")
    public ApiResponse<RevealSecretResponse> revealGet(
            @Parameter(description = "Access token from secret creation") @PathVariable String token,
            @RequestParam(required = false) String passphrase,
            HttpServletRequest httpRequest) {
        rateLimiter.check(clientIpResolver.resolve(httpRequest), IpRateLimiter.BucketType.REVEAL);
        return ApiResponse.of(secretService.reveal(token, passphrase));
    }

    @PostMapping("/{token}/reveal")
    @Operation(summary = "Reveal a secret (POST)", description = "Same as GET reveal; passphrase can be sent in the JSON body.")
    public ApiResponse<RevealSecretResponse> revealPost(
            @PathVariable String token,
            @RequestBody(required = false) RevealSecretRequest request,
            HttpServletRequest httpRequest) {
        rateLimiter.check(clientIpResolver.resolve(httpRequest), IpRateLimiter.BucketType.REVEAL);
        String passphrase = request != null ? request.passphrase() : null;
        return ApiResponse.of(secretService.reveal(token, passphrase));
    }

    @GetMapping("/{token}/status")
    @Operation(summary = "Check secret status", description = "Returns expiry and view limits without revealing content.")
    public ApiResponse<SecretStatusResponse> status(@PathVariable String token, HttpServletRequest httpRequest) {
        rateLimiter.check(clientIpResolver.resolve(httpRequest), IpRateLimiter.BucketType.STATUS);
        return ApiResponse.of(secretService.status(token));
    }

    @DeleteMapping("/{token}")
    @Operation(summary = "Delete a secret early", description = "Requires the delete token in the X-Delete-Token header.")
    public ResponseEntity<Void> delete(
            @PathVariable String token,
            @RequestHeader(DELETE_TOKEN_HEADER) String deleteToken) {
        secretService.delete(token, deleteToken);
        return ResponseEntity.noContent().build();
    }
}