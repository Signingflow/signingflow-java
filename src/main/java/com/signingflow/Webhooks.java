package com.signingflow;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Webhooks {
    private Webhooks() {}

    public static Event constructEvent(byte[] payload, String signature, String secret, String previousSecret, String previousSignature) throws SigningflowException {
        if (payload == null) {
            throw new SigningflowException.SignatureVerificationException("Pass the raw request body.");
        }
        if (secret == null || secret.isEmpty()) {
            throw new SigningflowException.SignatureVerificationException("Webhook secret is required.");
        }
        String currentSignature = signature == null ? "" : signature;
        String priorSecret = previousSecret == null ? "" : previousSecret;
        String priorSignature = previousSignature == null ? "" : previousSignature;
        boolean current = !currentSignature.isEmpty() && equals(currentSignature, mac(secret, payload));
        boolean previous = !priorSecret.isEmpty() && !priorSignature.isEmpty() && equals(priorSignature, mac(priorSecret, payload));
        if (!current && !previous) {
            throw new SigningflowException.SignatureVerificationException("Webhook signature did not match.");
        }
        Object decoded;
        try {
            decoded = Json.read(new String(payload, StandardCharsets.UTF_8));
        } catch (SigningflowException.ApiException ex) {
            throw new SigningflowException.InvalidRequestException("The webhook body is not JSON.");
        }
        return new Event(decoded, sha256(payload));
    }

    public static String bodySha256(byte[] payload) {
        return sha256(payload);
    }

    private static String mac(String secret, byte[] body) throws SigningflowException.SignatureVerificationException {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return hex(hmac.doFinal(body));
        } catch (Exception ex) {
            throw new SigningflowException.SignatureVerificationException("Webhook signature did not match.");
        }
    }

    private static boolean equals(String left, String right) {
        byte[] a = left.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
        byte[] b = right.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
        if (a.length != b.length) {
            MessageDigest.isEqual(a, a);
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }

    private static String sha256(byte[] payload) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(payload));
        } catch (Exception ex) {
            return "";
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte bite : bytes) {
            out.append(String.format("%02x", bite));
        }
        return out.toString();
    }
}
