package com.signingflow;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public final class Urls {
    public static final String OFFICIAL_HOST = "api.signingflow.com";
    private static final Pattern SEGMENT = Pattern.compile("^[A-Za-z0-9_-]+$");

    private Urls() {}

    public static String rfc3986(String value) {
        StringBuilder out = new StringBuilder();
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        for (byte bite : bytes) {
            int c = bite & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
                out.append((char) c);
            } else {
                out.append(String.format("%%%02X", c));
            }
        }
        return out.toString();
    }

    public static String fill(String template, Map<String, String> params) throws SigningflowException.InvalidRequestException {
        StringBuilder out = new StringBuilder();
        int index = 0;
        while (index < template.length()) {
            int start = template.indexOf('{', index);
            if (start < 0) {
                out.append(template.substring(index));
                break;
            }
            out.append(template, index, start);
            int end = template.indexOf('}', start);
            if (end < 0) {
                throw new SigningflowException.InvalidRequestException("invalid path");
            }
            String token = template.substring(start + 1, end);
            String name = token.split("=", 2)[0];
            String shortName = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : name;
            String value = params == null ? "" : params.getOrDefault(name, params.getOrDefault(shortName, ""));
            if (value.isEmpty() && (shortName.equals("name") || shortName.startsWith("name_"))) {
                value = params == null ? "" : params.getOrDefault("name", "");
            }
            if (value.isEmpty()) {
                throw new SigningflowException.InvalidRequestException("missing path param " + shortName);
            }
            String[] parts = value.split("/", -1);
            for (int i = 0; i < parts.length; i++) {
                if (!SEGMENT.matcher(parts[i]).matches()) {
                    throw new SigningflowException.InvalidRequestException("invalid path param " + shortName);
                }
                if (i > 0) {
                    out.append('/');
                }
                out.append(rfc3986(parts[i]));
            }
            index = end + 1;
        }
        return out.toString();
    }

    public static String resolve(String baseUrl, String path, Map<String, String> query) throws SigningflowException.InvalidRequestException {
        URI base = parse(baseUrl);
        if (!path.startsWith("/")) {
            throw new SigningflowException.InvalidRequestException("invalid path");
        }
        String origin = origin(base);
        String full = origin + path;
        URI built = parse(full);
        if (!sameOrigin(base, built)) {
            throw new SigningflowException.InvalidRequestException("invalid path");
        }
        String rawQuery = encode(query);
        String url = origin + (built.getRawPath() == null || built.getRawPath().isEmpty() ? "/" : built.getRawPath());
        if (!rawQuery.isEmpty()) {
            url += "?" + rawQuery;
        }
        return url;
    }

    public static String encode(Map<String, String> query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        List<String> pairs = new ArrayList<>();
        for (Map.Entry<String, String> entry : query.entrySet()) {
            String value = entry.getValue();
            if (value == null || value.isEmpty()) {
                continue;
            }
            pairs.add(rfc3986(entry.getKey()) + "=" + rfc3986(value));
        }
        return String.join("&", pairs);
    }

    public static boolean containsSecret(String rawQuery, String secret) {
        if (secret == null || secret.isEmpty() || rawQuery == null || rawQuery.isEmpty()) {
            return false;
        }
        if (rawQuery.contains(secret) || rawQuery.contains(rfc3986(secret)) || rawQuery.contains(Redact.formEncode(secret))) {
            return true;
        }
        if (badPercent(rawQuery)) {
            return true;
        }
        for (String part : rawQuery.split("&", -1)) {
            int eq = part.indexOf('=');
            String value = eq < 0 ? part : part.substring(eq + 1);
            if (decoded(value, false).contains(secret) || decoded(value, true).contains(secret)) {
                return true;
            }
        }
        return false;
    }

    public static URI allowedUploadUrl(String raw, List<String> hosts) throws SigningflowException.InvalidRequestException {
        if (raw == null || raw.indexOf('\0') >= 0) {
            throw new SigningflowException.InvalidRequestException("upload url rejected");
        }
        URI uri = parse(raw);
        if (!"https".equals(uri.getScheme())) {
            throw new SigningflowException.InvalidRequestException("upload url must be https");
        }
        if (uri.getRawUserInfo() != null || (uri.getRawAuthority() != null && uri.getRawAuthority().indexOf('@') >= 0)) {
            throw new SigningflowException.InvalidRequestException("upload url rejected");
        }
        String host = hostOf(uri);
        if (host.endsWith(".")) {
            throw new SigningflowException.InvalidRequestException("upload url rejected");
        }
        String lower = host.toLowerCase(Locale.ROOT);
        for (String item : hosts) {
            if (lower.equals(item) || lower.endsWith("." + item)) {
                return uri;
            }
        }
        throw new SigningflowException.InvalidRequestException("upload host rejected");
    }

    public static Duration retryDelay(String retryAfter, String resetAfter, Instant now) {
        Instant when = parseTime(retryAfter);
        if (when == null) {
            when = parseTime(resetAfter);
        }
        if (when == null) {
            return Duration.ZERO;
        }
        long seconds = when.getEpochSecond() - now.getEpochSecond();
        if (seconds < 0) {
            return Duration.ZERO;
        }
        if (seconds > 60) {
            return Duration.ofSeconds(60);
        }
        return Duration.ofSeconds(seconds);
    }

    public static Instant parseTime(String value) {
        if (value == null) {
            return null;
        }
        String text = value.trim();
        if (text.isEmpty()) {
            return null;
        }
        if (text.endsWith("Z")) {
            text = text.substring(0, text.length() - 1) + "+00:00";
        }
        try {
            if (text.matches(".*(?:Z|[+-]\\d{2}:?\\d{2})$")) {
                return OffsetDateTime.parse(text).toInstant();
            }
            return OffsetDateTime.parse(text + "+00:00").toInstant();
        } catch (DateTimeParseException ex) {
            return null;
        }
    }

    public static String hostOf(URI uri) throws SigningflowException.InvalidRequestException {
        String authority = uri.getRawAuthority();
        if (authority == null || authority.isEmpty() || authority.indexOf('@') >= 0) {
            throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
        }
        if (authority.startsWith("[")) {
            int end = authority.indexOf(']');
            if (end < 0) {
                throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
            }
            return authority.substring(0, end + 1);
        }
        int colon = authority.lastIndexOf(':');
        if (colon > 0 && authority.indexOf(':') == colon) {
            return authority.substring(0, colon);
        }
        return authority;
    }

    public static URI parse(String raw) throws SigningflowException.InvalidRequestException {
        if (raw == null || raw.indexOf('\0') >= 0) {
            throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
        }
        try {
            URI uri = URI.create(raw);
            if (uri.getScheme() == null || uri.getRawAuthority() == null) {
                throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
            }
            return uri;
        } catch (IllegalArgumentException ex) {
            throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
        }
    }

    private static String origin(URI uri) throws SigningflowException.InvalidRequestException {
        return uri.getScheme() + "://" + uri.getRawAuthority();
    }

    private static boolean sameOrigin(URI left, URI right) throws SigningflowException.InvalidRequestException {
        return left.getScheme().equals(right.getScheme()) && hostOf(left).equals(hostOf(right)) && left.getPort() == right.getPort();
    }

    private static String decoded(String value, boolean plus) {
        String text = plus ? value.replace("+", " ") : value;
        try {
            return URLDecoder.decode(text, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return value;
        }
    }

    private static boolean badPercent(String raw) {
        for (int i = 0; i < raw.length(); i++) {
            if (raw.charAt(i) != '%') {
                continue;
            }
            if (i + 2 >= raw.length()) {
                return true;
            }
            if (Character.digit(raw.charAt(i + 1), 16) < 0 || Character.digit(raw.charAt(i + 2), 16) < 0) {
                return true;
            }
            i += 2;
        }
        return false;
    }
}
