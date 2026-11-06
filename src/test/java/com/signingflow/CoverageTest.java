package com.signingflow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CoverageTest {
    private static final String ENVELOPE = "envelopes/11111111-1111-4111-8111-111111111111";
    private static final String STORAGE = "storages/22222222-2222-4222-8222-222222222222";
    private static final Instant NOW = Instant.parse("2026-11-06T00:00:00Z");
    private static LocalTls server;

    @BeforeAll
    static void start() throws Exception {
        server = LocalTls.start();
    }

    @AfterAll
    static void stop() {
        server.close();
    }

    @BeforeEach
    void reset() {
        server.reset();
        Clock.now = () -> NOW;
        Clock.sleep = duration -> { };
    }

    @AfterEach
    void clock() {
        Clock.reset();
    }

    @Test
    void clockSleepsOnlyForAPositiveDelay() throws Exception {
        Clock.reset();
        Clock.pause(null);
        Clock.pause(Duration.ZERO);
        Clock.pause(Duration.ofMillis(-1));
        Clock.pause(Duration.ofMillis(1));
        assertTrue(Clock.instant().isAfter(Instant.EPOCH));
        Thread worker = new Thread(() -> {
            Clock.reset();
            Thread.currentThread().interrupt();
            Clock.pause(Duration.ofSeconds(30));
            assertTrue(Thread.currentThread().isInterrupted());
        });
        worker.start();
        worker.join();
    }

    @Test
    void jsonCoversScalarsEscapesAndRejections() throws Exception {
        Object decoded = Json.read(" { \"a\" : [ true, false, null, -2, 0, 1.5, 2e1, \"x\\/\\b\\f\\n\\r\\t\\u0041\" ] } ");
        List<?> list = (List<?>) Json.asMap(decoded).get("a");
        assertEquals(Boolean.TRUE, list.get(0));
        assertEquals(Boolean.FALSE, list.get(1));
        assertNull(list.get(2));
        assertEquals(-2L, list.get(3));
        assertEquals(20.0, (Double) list.get(6), 0.001);
        assertEquals("x/\b\f\n\r\tA", list.get(7));
        assertEquals("{\"a\":1}", Json.write(Map.of("a", 1)));
        assertEquals("[1]", Json.write(List.of(1)));
        assertEquals("\"\\u0001\"", Json.write("\u0001"));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read((String) null));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read(""));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("tru"));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("nul"));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("\"\\q\""));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("\"\\u12\""));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("\"\\u12zz\""));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("\"\u0001\""));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("{"));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("{\"a\"}"));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("[1,]"));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("-"));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("1."));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("1e"));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("01"));
        assertEquals(1L, Json.read("1"));
        assertNull(Json.asInt(Long.MAX_VALUE));
        assertEquals(12, Json.asInt("12"));
        assertNull(Json.asInt("nope"));
        assertNull(Json.asMap(List.of()));
        Map<Object, Object> badKey = new LinkedHashMap<>();
        badKey.put(1, "a");
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Json.write(badKey));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Json.write(Double.POSITIVE_INFINITY));
        Map<String, Object> nested = Map.of();
        for (int i = 0; i < 40; i++) {
            nested = Map.of("a", nested);
        }
        Map<String, Object> tooDeep = nested;
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Json.write(tooDeep));
        assertEquals(2, Json.asInt(2.9));
    }

    @Test
    void urlsCoverHostsQueriesAndDelays() throws Exception {
        assertEquals("/v1/envelopes/abc:view", Urls.fill("/v1/{name_1}:view", Map.of("name", "envelopes/abc")));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.fill("/v1/{name}", Map.of()));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.fill("/v1/{name}", Map.of("name", "a/../b")));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.fill("/v1/{", Map.of()));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.resolve("https://api.signingflow.com", "v1", Map.of()));
        assertEquals("", Urls.encode(null));
        assertEquals("a=b", Urls.encode(Map.of("a", "b", "empty", "")));
        assertTrue(Urls.containsSecret("a=" + Urls.rfc3986("df_sk_a/b c+"), "df_sk_a/b c+"));
        assertTrue(Urls.containsSecret("a=" + Redact.formEncode("df_sk_a/b c+"), "df_sk_a/b c+"));
        assertTrue(Urls.containsSecret("a=%", "df_sk_test"));
        assertTrue(Urls.containsSecret("a=%zz", "df_sk_test"));
        assertFalse(Urls.containsSecret("a=b", ""));
        assertFalse(Urls.containsSecret("directory=needAction", "df_sk_test"));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.allowedUploadUrl(null, List.of("storage.googleapis.com")));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.allowedUploadUrl("https://storage.googleapis.com.\u0000/a", List.of("storage.googleapis.com")));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.allowedUploadUrl("https://storage.googleapis.com./a", List.of("storage.googleapis.com")));
        assertEquals("BUCKET.storage.googleapis.com", Urls.hostOf(Urls.allowedUploadUrl("https://BUCKET.storage.googleapis.com/a", List.of("storage.googleapis.com"))));
        assertEquals(Duration.ZERO, Urls.retryDelay("2020-01-01T00:00:00Z", "", NOW));
        assertEquals(Duration.ofSeconds(30), Urls.retryDelay("", "2026-11-06T00:00:30Z", NOW));
        assertEquals(Duration.ZERO, Urls.retryDelay("not", "also", NOW));
        assertNull(Urls.parseTime(null));
        assertNull(Urls.parseTime("  "));
        assertEquals(NOW, Urls.parseTime("2026-11-06T00:00:00"));
        assertEquals(NOW, Urls.parseTime("2026-11-06T00:00:00+00:00"));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.hostOf(URI.create("https://user@api.signingflow.com/")));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.parse(null));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.parse("https://api.signingflow.com/\u0000"));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.parse("not a url"));
        assertEquals("api.signingflow.com", Urls.hostOf(URI.create("https://api.signingflow.com:444/v1")));
        assertEquals("?token=[redacted]&sig=[redacted]", Redact.text("?token=abc&sig=def", ""));
        assertEquals(List.of(), Redact.violations(null, "df_sk_test"));
        new SigningflowException("x", 1, null, null, null, null, null, null, null, null, null);
        new SigningflowException.FieldViolation(null, null);
    }

    @Test
    void optionsAndModelsCoverRejections() throws Exception {
        ClientOptions custom = ClientOptions.builder()
                .workspaceId(" ws ")
                .env("live")
                .baseUrl("https://files.example.com")
                .allowCustomBaseUrl(true)
                .uploadHosts(List.of(" files.example.com ", "", "a.b.example"))
                .build();
        assertEquals("LIVE", custom.wireEnv());
        assertEquals(List.of("files.example.com", "a.b.example"), custom.uploadHosts());
        assertThrows(SigningflowException.InvalidRequestException.class, () -> ClientOptions.builder().workspaceId("ws").env("sandbox").uploadHosts(List.of("a..b.com")).build());
        assertThrows(SigningflowException.InvalidRequestException.class, () -> ClientOptions.builder().workspaceId("ws").env("sandbox").uploadHosts(List.of("example.com.")).build());
        assertThrows(SigningflowException.InvalidRequestException.class, () -> ClientOptions.builder().workspaceId("a\nb").env("sandbox").build());
        assertThrows(SigningflowException.InvalidRequestException.class, () -> new SigningflowClient("df_sk_test", ClientOptions.builder().workspaceId("ws").env("sandbox").funnel("a\u0000b").build()));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> ClientOptions.builder().workspaceId("ws").env("sandbox").timeout(Duration.ofMillis(-1)).build());
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Models.envelopeName("nope"));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Models.templateName("templates/nope"));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Models.webhookName("webhook/1"));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Models.deliveryName("webhooks/nope"));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Models.cleanRecipients(null));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Models.cleanRecipients(List.of(new Recipient("Ada", "not-an-email"))));
        Envelope decoded = Models.decode(Map.of("envelope", Map.of("uid", "11111111-1111-4111-8111-111111111111", "documents", List.of("skip", Map.of("uid", "doc")))));
        assertEquals(1, decoded.documents().size());
        assertEquals(ENVELOPE, Models.nameOf(Map.of("uid", "11111111-1111-4111-8111-111111111111")));
        assertEquals("", Models.nameOf("nope"));
        assertNull(Models.findStorage(Map.of("storages", List.of(Map.of("name", "storages/not-a-uuid", "pre_signed_url", "https://example.com")))));
        assertEquals(STORAGE, Models.findStorage(List.of(Map.of("name", STORAGE, "preSignedUrl", "https://example.com/a")))[0]);
        Path root = Files.createTempDirectory("signingflow-more");
        try {
            Files.createDirectory(root.resolve("dir"));
            assertEquals("The file could not be read.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "dir")).getMessage());
            assertEquals("The file could not be read.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "missing.pdf")).getMessage());
            assertEquals("The path is outside upload_root.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), ".")).getMessage());
            assertEquals("The path is outside upload_root.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "a\u0000b")).getMessage());
        } finally {
            delete(root);
        }
        assertEquals("Unknown operation.", assertThrows(SigningflowException.class, () -> Allowlist.operation("")).getMessage());
        assertEquals("POST", Allowlist.operation("EnvelopeService_AddEnvelope").http());
    }

    @Test
    void moreApiBranches() throws Exception {
        SigningflowClient api = client(Map.of("channel", "desk", "funnel", "mail"));
        server.json("");
        Envelope empty = api.envelopes().retrieve(ENVELOPE, "");
        assertEquals(ENVELOPE, empty.name());
        assertEquals("desk", server.hits.get(0).header("x-request-channel"));
        assertEquals("mail", server.hits.get(0).header("x-request-funnel"));

        server.reset();
        server.bytes(200, gzipHello(), "text/plain", Map.of());
        assertThrows(SigningflowException.ApiException.class, () -> client(Map.of()).envelopes().retrieve(ENVELOPE, ""));

        server.reset();
        server.json(408, "{\"message\":\"again\"}");
        server.json("{\"name\":\"" + ENVELOPE + "\"}");
        assertEquals(ENVELOPE, client(Map.of()).envelopes().retrieve(ENVELOPE, "name").name());

        server.reset();
        String upload = "https://127.0.0.1:" + server.port + "/bucket/a";
        server.json("{\"storages\":[{\"name\":\"" + STORAGE + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        server.json(200, "");
        server.json("{}");
        server.json("{\"ok\":true}");
        assertTrue(assertThrows(SigningflowException.ApiException.class, () -> client(Map.of()).envelopes().sendDocument("Title", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), "")).getMessage().contains("envelope name"));

        server.reset();
        String bare = "https://127.0.0.1:" + server.port + "/bucket/a";
        server.json("{\"storages\":[{\"name\":\"" + STORAGE + "\",\"pre_signed_url\":\"" + bare + "\"}]}");
        server.json(200, "");
        server.json("{}");
        server.json("{\"envelope\":{\"name\":\"" + ENVELOPE + "\"}}");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"documents\":[]}");
        assertEquals("The draft has no document to address.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).envelopes().sendDocument("Title", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), "")).getMessage());

        server.reset();
        scriptDraft();
        server.json(400, "{\"message\":\"bad patch\"}");
        assertEquals(ENVELOPE, assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).envelopes().sendDocument("Title", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), "")).envelopeName());

        server.reset();
        scriptDraft();
        server.json(409, "{\"message\":\"idempotency used\",\"metadata\":{\"resource_id\":\"envelopes/other\"}}");
        assertEquals(ENVELOPE, assertThrows(SigningflowException.IdempotencyException.class, () -> client(Map.of()).envelopes().sendDocument("Title", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), "")).envelopeName());

        server.reset();
        scriptDraft();
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        server.json(500, "{\"message\":\"view failed\"}");
        assertEquals(ENVELOPE, assertThrows(SigningflowException.ConnectionException.class, () -> client(Map.of()).envelopes().sendDocument("Title", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), "")).envelopeName());

        server.reset();
        server.json("{\"name\":\"" + ENVELOPE + "\"}");
        assertEquals(ENVELOPE, client(Map.of()).envelopes().update(ENVELOPE, Map.of()).name());
        server.json("{\"uri\":\"https://files.example/a\",\"downloadTime\":\"2026-11-06T00:00:00Z\",\"etag\":\"e\"}");
        assertEquals("e", client(Map.of()).envelopes().download(ENVELOPE).etag());

        server.reset();
        assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookUrls().create("x".repeat(101), "https://example.com", List.of("A"), null, ""));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookUrls().create("Hooks", "://", List.of("A"), null, ""));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookUrls().create("Hooks", "https://example.com", null, null, ""));
        assertTrue(assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookUrls().create("Hooks", "https://example.com", List.of("A"), "NONE", "")).getMessage().contains("NONE"));
        assertEquals("", WebhookUrls.signingSecretOf("nope"));
        assertEquals("", WebhookUrls.signingSecretOf(new WebhookUrl("", "", "", List.of(), "")));
        server.json("{\"webhooks\":[\"skip\",{\"name\":\"webhooks/11111111-1111-4111-8111-111111111111\",\"event\":\"A\"}],\"nextPageToken\":\"\"}");
        assertEquals(1, client(Map.of()).webhookDeliveries().list(1000, "").data().size());
        assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookDeliveries().list(1001, null));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).envelopes().create("Title", "", "", ""));
        assertEquals("127.0.0.1", Urls.allowedUploadUrl("https://127.0.0.1:" + server.port + "/a", List.of("127.0.0.1")).getHost());
        server.json("{\"storages\":[{\"name\":\"" + STORAGE + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        server.json(200, "");
        server.json("{}");
        StoredFile notes = client(Map.of()).files().create(new byte[0], null, "notes.txt", "", "11111111-1111-4111-8111-111111111111");
        assertEquals(STORAGE, notes.name());
        assertTrue(server.hits.get(server.hits.size() - 3).text().contains("text/plain"));
    }

    private void scriptDraft() {
        String upload = "https://127.0.0.1:" + server.port + "/bucket/a";
        server.json("{\"storages\":[{\"name\":\"" + STORAGE + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        server.json(200, "");
        server.json("{}");
        server.json("{\"envelope\":{\"name\":\"" + ENVELOPE + "\"}}");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"documents\":[{\"uid\":\"doc-1\",\"display_name\":\"Contract\"}]}");
        server.json("{\"name\":\"" + ENVELOPE + "\"}");
    }

    private SigningflowClient client(Map<String, Object> overrides) throws SigningflowException.InvalidRequestException {
        return new SigningflowClient("df_sk_test", ClientOptions.builder()
                .workspaceId("ws")
                .env("sandbox")
                .baseUrl("https://127.0.0.1:" + server.port)
                .allowCustomBaseUrl(true)
                .timeout(Duration.ofMillis(Long.parseLong(String.valueOf(overrides.getOrDefault("timeout", "2000")))))
                .maxNetworkRetries(Integer.parseInt(String.valueOf(overrides.getOrDefault("retries", "2"))))
                .uploadHosts(List.of("127.0.0.1"))
                .channel((String) overrides.getOrDefault("channel", ""))
                .funnel((String) overrides.getOrDefault("funnel", ""))
                .caBundle(server.certificate.toString())
                .build());
    }

    private static byte[] gzipHello() {
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            try (java.util.zip.GZIPOutputStream gzip = new java.util.zip.GZIPOutputStream(out)) {
                gzip.write("{\"name\":\"envelopes/11111111-1111-4111-8111-111111111111\"}".getBytes(StandardCharsets.UTF_8));
            }
            return out.toByteArray();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static void delete(Path root) throws Exception {
        try (var walk = Files.walk(root)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                    // Best-effort cleanup.
                }
            });
        }
    }
}
