package com.secretdrop.common.api;

import com.secretdrop.ratelimit.RateLimitExceededException;
import com.secretdrop.secret.SecretNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(SecretNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(SecretNotFoundException ex, HttpServletRequest request) {
        return build(HttpStatus.NOT_FOUND, "Not Found", ex.getMessage(), request.getRequestURI(), null);
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ErrorResponse> handleRateLimit(RateLimitExceededException ex, HttpServletRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, String.valueOf(ex.retryAfterSeconds()));
        ErrorResponse body = new ErrorResponse(
                Instant.now(),
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "Too Many Requests",
                ex.getMessage(),
                request.getRequestURI(),
                null);
        return new ResponseEntity<>(body, headers, HttpStatus.TOO_MANY_REQUESTS);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        List<ErrorResponse.FieldError> errors = ex.getBindingResult().getFieldErrors().stream()
                .map(this::toFieldError)
                .toList();
        return build(HttpStatus.BAD_REQUEST, "Bad Request", "Validation failed", request.getRequestURI(), errors);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(IllegalArgumentException ex, HttpServletRequest request) {
        return build(HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage(), request.getRequestURI(), null);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(Exception ex, HttpServletRequest request) {
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", "Unexpected error", request.getRequestURI(), null);
    }

    private ErrorResponse.FieldError toFieldError(FieldError fieldError) {
        return new ErrorResponse.FieldError(fieldError.getField(), fieldError.getDefaultMessage());
    }

    private ResponseEntity<ErrorResponse> build(
            HttpStatus status,
            String error,
            String message,
            String path,
            List<ErrorResponse.FieldError> fieldErrors) {
        ErrorResponse body = new ErrorResponse(Instant.now(), status.value(), error, message, path, fieldErrors);
        return ResponseEntity.status(status).body(body);
    }
}