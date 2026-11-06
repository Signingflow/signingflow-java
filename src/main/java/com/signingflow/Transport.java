package com.signingflow;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

final class Transport {
    static final int MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
    private static final Pattern UUID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", Pattern.CASE_INSENSITIVE);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ClientOptions options;
    private final String apiKey;
    private final HttpClient http;

    Transport(String apiKey, ClientOptions options) throws SigningflowException.InvalidRequestException {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        if (this.apiKey.isEmpty()) {
            throw new SigningflowException.InvalidRequestException("API key is required.");
        }
        if (ClientOptions.badHeader(this.apiKey) || ClientOptions.badHeader(options.workspaceId()) || ClientOptions.badHeader(options.channel()) || ClientOptions.badHeader(options.funnel())) {
            throw new SigningflowException.InvalidRequestException("invalid header value");
        }
        this.options = options;
        HttpClient.Builder builder = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(HttpClient.Builder.NO_PROXY)
                .connectTimeout(options.timeout());
        if (!options.caBundle().isEmpty()) {
            builder.sslContext(trust(options.caBundle()));
        }
        this.http = builder.build();
    }

    String apiKey() {
        return apiKey;
    }

    ClientOptions options() {
        return options;
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> call(String operationId, Map<String, String> pathParams, Map<String, String> query, Map<String, Object> body, String idempotencyKey) throws SigningflowException {
        Allowlist.Operation spec = Allowlist.operation(operationId);
        String key = "";
        Map<String, Object> payload = null;
        if (!"GET".equals(spec.http())) {
            payload = new LinkedHashMap<>();
            if (body != null) {
                payload.putAll(body);
            }
        }
        if (spec.idempotent()) {
            key = keyFor(idempotencyKey, body);
            payload.put("idempotencyKey", key);
        }
        String url;
        try {
            String path = Urls.fill(spec.path(), pathParams);
            url = Urls.resolve(options.baseUrl(), path, query);
        } catch (SigningflowException.InvalidRequestException error) {
            throw new SigningflowException.InvalidRequestException(error.getMessage(), error.statusCode(), error.grpcCode(), error.traceCode(), error.requestId(), key, error.capability(), error.resourceName(), error.envelopeName(), error.retryAfter(), error.fieldViolations());
        }
        String rawQuery = "";
        int q = url.indexOf('?');
        if (q >= 0) {
            rawQuery = url.substring(q + 1);
        }
        if (Urls.containsSecret(rawQuery, apiKey)) {
            throw new SigningflowException.InvalidRequestException("The API key must not be sent in the query string.", 0, null, "", "", key, "", "", "", "", List.of());
        }
        int retries = "GET".equals(spec.http()) || spec.idempotent() ? options.maxNetworkRetries() : 0;
        byte[] encoded = null;
        if (payload != null) {
            encoded = Json.write(payload).getBytes(StandardCharsets.UTF_8);
        }
        int attempt = 0;
        while (true) {
            HttpResult result;
            try {
                result = exchange(spec.http(), URI.create(url), encoded, headers(spec.http()));
            } catch (SigningflowException error) {
                throw error;
            } catch (IOException | InterruptedException error) {
                if (error instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                if (attempt < retries) {
                    attempt++;
                    continue;
                }
                throw connection(error, key);
            }
            if (result.status >= 200 && result.status < 300) {
                return parseSuccess(result);
            }
            if (attempt < retries && retryable(result.status)) {
                attempt++;
                Clock.pause(Urls.retryDelay(result.header("rate-limit-retry-after"), result.header("rate-limit-reset-after"), Clock.instant()));
                continue;
            }
            throw failure(result, spec.capability(), key);
        }
    }

    void putBytes(URI url, String contentType, byte[] data) throws SigningflowException {
        if (ClientOptions.badHeader(contentType)) {
            throw new SigningflowException.InvalidRequestException("invalid header value");
        }
        int retries = options.maxNetworkRetries();
        int attempt = 0;
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", contentType);
        headers.put("x-goog-if-generation-match", "0");
        headers.put("Accept-Encoding", "identity");
        while (true) {
            HttpResult result;
            try {
                result = exchange("PUT", url, data == null ? new byte[0] : data, headers);
            } catch (SigningflowException error) {
                throw error;
            } catch (IOException | InterruptedException error) {
                if (error instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                if (attempt < retries) {
                    attempt++;
                    continue;
                }
                throw new SigningflowException.ConnectionException("The upload could not be reached.", 0, "");
            }
            if ((result.status >= 200 && result.status < 300) || result.status == 412) {
                return;
            }
            if (attempt < retries && result.status >= 500) {
                attempt++;
                continue;
            }
            throw new SigningflowException.ApiException("Uploading the file to storage failed.", result.status);
        }
    }

    private Map<String, String> headers(String method) {
        Map<String, String> header = new LinkedHashMap<>();
        header.put("Authorization", "Bearer " + apiKey);
        header.put("X-Request-Workspace-Id", options.workspaceId());
        header.put("X-Request-Env", options.wireEnv());
        header.put("X-Request-Source", Version.SOURCE);
        header.put("Accept", "application/json");
        header.put("User-Agent", Version.SOURCE);
        header.put("Accept-Encoding", "identity");
        if (!options.channel().isEmpty()) {
            header.put("X-Request-Channel", options.channel());
        }
        if (!options.funnel().isEmpty()) {
            header.put("X-Request-Funnel", options.funnel());
        }
        if (!"GET".equals(method)) {
            header.put("Content-Type", "application/json");
        }
        return header;
    }

    private HttpResult exchange(String method, URI url, byte[] body, Map<String, String> headers) throws IOException, InterruptedException, SigningflowException {
        if (!"https".equalsIgnoreCase(url.getScheme()) || url.getHost() == null) {
            throw new SigningflowException.InvalidRequestException("url must be https");
        }
        for (String value : headers.values()) {
            if (ClientOptions.badHeader(value)) {
                throw new SigningflowException.InvalidRequestException("invalid header value");
            }
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(url).timeout(options.timeout());
        headers.forEach(request::header);
        if (body == null) {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            request.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
        }
        HttpResponse<InputStream> response = http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
        String declared = response.headers().firstValue("content-length").orElse("");
        byte[] captured;
        try (InputStream in = response.body()) {
            captured = readLimited(in, declared, response.statusCode());
        }
        Map<String, String> responseHeaders = new LinkedHashMap<>();
        response.headers().map().forEach((name, values) -> {
            if (!values.isEmpty()) {
                responseHeaders.put(name.toLowerCase(Locale.ROOT), values.get(0));
            }
        });
        return new HttpResult(response.statusCode(), responseHeaders, captured);
    }

    private static byte[] readLimited(InputStream in, String declared, int status) throws IOException, SigningflowException.ApiException {
        long expected = -1;
        if (declared.matches("\\d+")) {
            expected = Long.parseLong(declared);
            if (expected > MAX_RESPONSE_BYTES) {
                throw new SigningflowException.ApiException("The API response is larger than 8 MB.", status);
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        try {
            int read;
            while ((read = in.read(buf)) >= 0) {
                if ((long) out.size() + read > MAX_RESPONSE_BYTES) {
                    throw new SigningflowException.ApiException("The API response is larger than 8 MB.", status);
                }
                out.write(buf, 0, read);
            }
        } catch (IOException ex) {
            if (expected >= 0 && out.size() < expected) {
                throw new SigningflowException.ApiException("The API response ended before the declared length.", status);
            }
            throw ex;
        }
        if (expected >= 0 && out.size() < expected) {
            throw new SigningflowException.ApiException("The API response ended before the declared length.", status);
        }
        return out.toByteArray();
    }

    static String keyFor(String supplied, Map<String, Object> body) throws SigningflowException.InvalidRequestException {
        String raw = supplied == null ? "" : supplied.trim();
        if (raw.isEmpty() && body != null && body.get("idempotencyKey") instanceof String text) {
            raw = text.trim();
        }
        if (raw.isEmpty()) {
            return uuid4();
        }
        if (!UUID.matcher(raw).matches()) {
            throw new SigningflowException.InvalidRequestException("idempotencyKey must be a UUID.");
        }
        return raw;
    }

    static String uuid4() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x40);
        bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i == 4 || i == 6 || i == 8 || i == 10) {
                out.append('-');
            }
            out.append(String.format("%02x", bytes[i]));
        }
        return out.toString();
    }

    private SigningflowException failure(HttpResult result, String capability, String key) {
        String raw = new String(result.body, StandardCharsets.UTF_8);
        Object parsed = raw;
        if (!raw.isBlank()) {
            try {
                parsed = Json.read(raw);
            } catch (SigningflowException.ApiException ignored) {
                parsed = raw;
            }
        }
        String message = Values.serverMessage(parsed);
        if (message.isEmpty()) {
            message = raw.isBlank() ? "Request failed with status " + result.status + "." : raw;
        }
        String retry = result.header("rate-limit-retry-after");
        if (retry.isEmpty()) {
            retry = result.header("rate-limit-reset-after");
        }
        List<SigningflowException.FieldViolation> fields = Redact.violations(Values.fieldViolations(parsed), apiKey);
        message = Redact.message(message, apiKey);
        int status = result.status;
        Integer grpc = Values.grpcCode(parsed);
        String trace = Values.traceCode(parsed);
        String requestId = result.header("x-request-id");
        if (status == 401) {
            return new SigningflowException.AuthenticationException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
        }
        if (status == 403) {
            return new SigningflowException.PermissionException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
        }
        if (status == 409 && Values.mentionsIdempotency(parsed)) {
            return new SigningflowException.IdempotencyException(message, status, grpc, trace, requestId, key, capability, Values.resourceName(parsed), "", retry, fields);
        }
        if (status == 429) {
            return new SigningflowException.RateLimitException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
        }
        if (status >= 400 && status < 500) {
            return new SigningflowException.InvalidRequestException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
        }
        return new SigningflowException.ApiException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseSuccess(HttpResult result) throws SigningflowException.ApiException {
        String raw = new String(result.body, StandardCharsets.UTF_8);
        if (raw.isBlank()) {
            return new LinkedHashMap<>();
        }
        String type = result.header("content-type");
        if (!type.isEmpty() && !type.contains("json") && !type.contains("text/")) {
            throw new SigningflowException.ApiException("The API returned a non-JSON body.", result.status);
        }
        if (type.toLowerCase(Locale.ROOT).contains("gzip") || result.header("content-encoding").toLowerCase(Locale.ROOT).contains("gzip") || gzip(result.body)) {
            throw new SigningflowException.ApiException("The API returned invalid JSON.", result.status);
        }
        Object decoded;
        try {
            decoded = Json.read(raw);
        } catch (SigningflowException.ApiException ex) {
            throw new SigningflowException.ApiException("The API returned invalid JSON.", result.status);
        }
        if (!(decoded instanceof Map<?, ?> map)) {
            throw new SigningflowException.ApiException("The API returned invalid JSON.", result.status);
        }
        return (Map<String, Object>) map;
    }

    private static boolean gzip(byte[] body) {
        return body.length >= 2 && (body[0] & 0xff) == 0x1f && (body[1] & 0xff) == 0x8b;
    }

    private static boolean retryable(int status) {
        return status == 408 || status == 429 || status >= 500;
    }

    private static SigningflowException.ConnectionException connection(Throwable error, String key) {
        String text = error.getMessage() == null ? "" : error.getMessage().toLowerCase(Locale.ROOT);
        if (text.contains("timed out") || text.contains("timeout")) {
            return new SigningflowException.ConnectionException("The API timed out.", 408, key);
        }
        return new SigningflowException.ConnectionException("The API could not be reached.", 0, key);
    }

    private static SSLContext trust(String pemPath) throws SigningflowException.InvalidRequestException {
        try (InputStream in = java.nio.file.Files.newInputStream(java.nio.file.Path.of(pemPath))) {
            var certificate = CertificateFactory.getInstance("X.509").generateCertificate(in);
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null);
            store.setCertificateEntry("signingflow-probe", certificate);
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(store);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return context;
        } catch (Exception ex) {
            throw new SigningflowException.InvalidRequestException("ca_bundle could not be read.");
        }
    }

    private record HttpResult(int status, Map<String, String> headers, byte[] body) {
        private String header(String name) {
            return headers.getOrDefault(name, "");
        }
    }
}
