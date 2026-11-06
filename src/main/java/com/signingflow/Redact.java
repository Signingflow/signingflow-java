package com.signingflow;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

public final class Redact {
    private static final Pattern SECRET_KEY = Pattern.compile("df_sk_[A-Za-z0-9_-]+");
    private static final Pattern BEARER = Pattern.compile("Bearer\\s+\\S+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SIGNED_QUERY = Pattern.compile("([?&](?:X-Goog-Signature|Signature|sig|token)=)[^&\\s\"]+", Pattern.CASE_INSENSITIVE);
    private static final String PLACEHOLDER = "df_sk_redacted";

    private Redact() {}

    public static String text(String value, String secret) {
        String cleaned = value == null ? "" : value;
        for (String form : forms(secret)) {
            cleaned = cleaned.replace(form, PLACEHOLDER);
        }
        cleaned = SECRET_KEY.matcher(cleaned).replaceAll(PLACEHOLDER);
        cleaned = BEARER.matcher(cleaned).replaceAll("Bearer [redacted]");
        return SIGNED_QUERY.matcher(cleaned).replaceAll("$1[redacted]");
    }

    public static String message(String value, String secret) {
        String cleaned = text(value, secret);
        if (cleaned.length() <= 500) {
            return cleaned;
        }
        return cleaned.substring(0, 500) + "…";
    }

    public static List<SigningflowException.FieldViolation> violations(List<SigningflowException.FieldViolation> items, String secret) {
        List<SigningflowException.FieldViolation> out = new ArrayList<>();
        if (items == null) {
            return out;
        }
        for (SigningflowException.FieldViolation item : items) {
            out.add(new SigningflowException.FieldViolation(message(item.field(), secret), message(item.description(), secret)));
        }
        return out;
    }

    static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static List<String> forms(String secret) {
        if (secret == null || secret.isEmpty()) {
            return List.of();
        }
        List<String> forms = new ArrayList<>();
        for (String form : List.of(secret, Urls.rfc3986(secret), formEncode(secret))) {
            if (!form.isEmpty() && !forms.contains(form)) {
                forms.add(form);
            }
        }
        forms.sort(Comparator.comparingInt(String::length).reversed());
        return forms;
    }
}
