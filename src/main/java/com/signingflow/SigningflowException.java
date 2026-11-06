package com.signingflow;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Every SDK error. Catch this to handle all of them. */
public class SigningflowException extends Exception {
    private final int statusCode;
    private final Integer grpcCode;
    private final String traceCode;
    private final String requestId;
    private final String idempotencyKey;
    private final String capability;
    private final String resourceName;
    private String envelopeName;
    private final String retryAfter;
    private final List<FieldViolation> fieldViolations;

    public SigningflowException(String message) {
        this(message, 0, null, "", "", "", "", "", "", "", List.of());
    }

    public SigningflowException(
            String message,
            int statusCode,
            Integer grpcCode,
            String traceCode,
            String requestId,
            String idempotencyKey,
            String capability,
            String resourceName,
            String envelopeName,
            String retryAfter,
            List<FieldViolation> fieldViolations) {
        super(message == null ? "" : message);
        this.statusCode = statusCode;
        this.grpcCode = grpcCode;
        this.traceCode = traceCode == null ? "" : traceCode;
        this.requestId = requestId == null ? "" : requestId;
        this.idempotencyKey = idempotencyKey == null ? "" : idempotencyKey;
        this.capability = capability == null ? "" : capability;
        this.resourceName = resourceName == null ? "" : resourceName;
        this.envelopeName = envelopeName == null ? "" : envelopeName;
        this.retryAfter = retryAfter == null ? "" : retryAfter;
        this.fieldViolations = List.copyOf(fieldViolations == null ? List.of() : fieldViolations);
    }

    public int statusCode() {
        return statusCode;
    }

    public Integer grpcCode() {
        return grpcCode;
    }

    public String traceCode() {
        return traceCode;
    }

    public String requestId() {
        return requestId;
    }

    public String idempotencyKey() {
        return idempotencyKey;
    }

    public String capability() {
        return capability;
    }

    public String resourceName() {
        return resourceName;
    }

    public String envelopeName() {
        return envelopeName;
    }

    public String retryAfter() {
        return retryAfter;
    }

    public List<FieldViolation> fieldViolations() {
        return fieldViolations;
    }

    public SigningflowException attach(String name) {
        this.envelopeName = name == null ? "" : name;
        return this;
    }

    public static final class FieldViolation {
        private final String field;
        private final String description;

        public FieldViolation(String field, String description) {
            this.field = field == null ? "" : field;
            this.description = description == null ? "" : description;
        }

        public String field() {
            return field;
        }

        public String description() {
            return description;
        }
    }

    public static final class AuthenticationException extends SigningflowException {
        public AuthenticationException(String message, int statusCode, Integer grpcCode, String traceCode, String requestId, String idempotencyKey, String capability, String resourceName, String envelopeName, String retryAfter, List<FieldViolation> fieldViolations) {
            super(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations);
        }
    }

    public static final class PermissionException extends SigningflowException {
        public PermissionException(String message, int statusCode, Integer grpcCode, String traceCode, String requestId, String idempotencyKey, String capability, String resourceName, String envelopeName, String retryAfter, List<FieldViolation> fieldViolations) {
            super(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations);
        }
    }

    public static final class IdempotencyException extends SigningflowException {
        public IdempotencyException(String message, int statusCode, Integer grpcCode, String traceCode, String requestId, String idempotencyKey, String capability, String resourceName, String envelopeName, String retryAfter, List<FieldViolation> fieldViolations) {
            super(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations);
        }
    }

    public static final class RateLimitException extends SigningflowException {
        public RateLimitException(String message, int statusCode, Integer grpcCode, String traceCode, String requestId, String idempotencyKey, String capability, String resourceName, String envelopeName, String retryAfter, List<FieldViolation> fieldViolations) {
            super(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations);
        }
    }

    public static final class InvalidRequestException extends SigningflowException {
        public InvalidRequestException(String message) {
            super(message);
        }

        public InvalidRequestException(String message, int statusCode, Integer grpcCode, String traceCode, String requestId, String idempotencyKey, String capability, String resourceName, String envelopeName, String retryAfter, List<FieldViolation> fieldViolations) {
            super(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations);
        }
    }

    public static final class ApiException extends SigningflowException {
        public ApiException(String message) {
            super(message);
        }

        public ApiException(String message, int statusCode) {
            super(message, statusCode, null, "", "", "", "", "", "", "", List.of());
        }

        public ApiException(String message, int statusCode, Integer grpcCode, String traceCode, String requestId, String idempotencyKey, String capability, String resourceName, String envelopeName, String retryAfter, List<FieldViolation> fieldViolations) {
            super(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations);
        }
    }

    public static final class ConnectionException extends SigningflowException {
        public ConnectionException(String message, int statusCode, String idempotencyKey) {
            super(message, statusCode, null, "", "", idempotencyKey, "", "", "", "", List.of());
        }
    }

    public static final class SignatureVerificationException extends SigningflowException {
        public SignatureVerificationException(String message) {
            super(message);
        }
    }

    static List<FieldViolation> copyViolations(List<FieldViolation> items) {
        return Collections.unmodifiableList(new ArrayList<>(items));
    }
}
