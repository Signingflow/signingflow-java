package com.signingflow;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.ServerSocket;
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
import java.util.zip.GZIPOutputStream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class SdkTest {
    private static final String ENVELOPE = "envelopes/11111111-1111-4111-8111-111111111111";
    private static final String TEMPLATE = "templates/11111111-1111-4111-8111-111111111111";
    private static final String WEBHOOK = "webhookUrls/11111111-1111-4111-8111-111111111111";
    private static final String DELIVERY = "webhooks/11111111-1111-4111-8111-111111111111";
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
    void clock() {
        server.reset();
        Clock.now = () -> NOW;
        Clock.sleep = duration -> { };
    }

    @AfterEach
    void restoreClock() {
        Clock.reset();
    }

    @Test
    void configRejectsUnsafeValues() throws Exception {
        assertEquals("workspace_id is required.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("workspace", ""))).getMessage());
        assertEquals("API key is required.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("key", "  "))).getMessage());
        assertEquals("env must be sandbox or live.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("env", "prod"))).getMessage());
        assertEquals("base_url must be https.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("base", "http://api.signingflow.com"))).getMessage());
        assertEquals("base_url must not include a username or password.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("base", "https://user:pass@api.signingflow.com"))).getMessage());
        assertTrue(assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("base", "https://API.SIGNINGFLOW.COM"))).getMessage().contains("api.signingflow.com"));
        assertEquals("timeout must be positive.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("timeout", "0"))).getMessage());
        assertEquals("max_network_retries must be a whole number of zero or more.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("retries", "-1"))).getMessage());
        assertEquals("invalid header value", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("key", "df_sk_a\nb"))).getMessage());
        assertEquals("invalid header value", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("channel", "a\rb"))).getMessage());
        assertTrue(assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("hosts", List.of("evil.com")))).getMessage().contains("upload_hosts"));
        assertTrue(assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("hosts", List.of(".example.com")))).getMessage().contains("upload_hosts"));
        assertEquals("ca_bundle could not be read.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("ca", server.certificate.getParent().resolve("missing.pem").toString()))).getMessage());
        assertEquals("workspace_id is required.", assertThrows(SigningflowException.InvalidRequestException.class, () -> new SigningflowClient("df_sk_test", null)).getMessage());
        SigningflowClient live = client(Map.of("env", "LIVE", "base", "https://api.signingflow.com:444/", "channel", " desk ", "funnel", " mail "));
        assertEquals("LIVE", live.options().wireEnv());
        assertEquals("https://api.signingflow.com:444", live.options().baseUrl());
        assertEquals("desk", live.options().channel());
        assertEquals("mail", live.options().funnel());
    }

    @Test
    void sendDocumentAndUploadContract() throws Exception {
        String upload = "https://127.0.0.1:" + server.port + "/bucket/a";
        server.json("{\"storages\":[{\"name\":\"" + STORAGE + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        server.json(412, "");
        server.json("{}");
        server.json("{\"envelope\":{\"name\":\"" + ENVELOPE + "\",\"display_name\":\"Contract\"}}");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"display_name\":\"Contract\",\"documents\":[{\"uid\":\"doc-1\",\"display_name\":\"Contract\"}],\"compliance\":{\"profile\":\"QES\"}}");
        server.json("{\"name\":\"" + ENVELOPE + "\"}");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"sent_time\":\"2026-11-06T00:00:00Z\"}");
        Envelope sent = client(Map.of()).envelopes().sendDocument("Contract", "%PDF".getBytes(StandardCharsets.UTF_8), null, "contract.pdf", List.of(new Recipient("Ada", "ada@example.com")), "Please sign");
        assertEquals(ENVELOPE, sent.name());
        LocalTls.Hit put = null;
        for (LocalTls.Hit hit : server.hits) {
            assertEquals("identity", hit.header("accept-encoding"));
            assertFalse(hit.headers().containsKey("x-api-key"));
            if ("PUT".equals(hit.method())) {
                put = hit;
            }
        }
        assertEquals("application/pdf", put.header("content-type"));
        assertEquals("0", put.header("x-goog-if-generation-match"));
        assertEquals("", put.header("authorization"));
        LocalTls.Hit add = server.hits.get(0);
        assertEquals("Bearer df_sk_test", add.header("authorization"));
        assertEquals("ws", add.header("x-request-workspace-id"));
        assertEquals("SANDBOX", add.header("x-request-env"));
        assertEquals("signingflow-java/0.1.0", add.header("x-request-source"));
        assertTrue(add.text().contains("idempotencyKey"));
        assertTrue(add.text().contains("application/pdf"));
        assertFalse(server.hits.stream().anyMatch(hit -> hit.path().contains("/secret")));
    }

    @Test
    void refusesEncodedApiKeyBeforeCalling() {
        String secret = "df_sk_a/b c+";
        server.json("{\"envelopes\":[]}");
        SigningflowException.InvalidRequestException error = assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("key", secret)).envelopes().list(secret, null, null, null));
        assertEquals("The API key must not be sent in the query string.", error.getMessage());
        assertEquals(0, server.hits.size());
        assertTrue(Urls.containsSecret("directory=" + Urls.rfc3986(secret), secret));
        assertTrue(Urls.containsSecret("pageToken=%zz", secret));
        assertFalse(Urls.containsSecret("", secret));
    }

    @Test
    void redactsSlashKeyFromAnApiError() {
        String secret = "df_sk_a/b c+";
        String echoed = secret + " " + Urls.rfc3986(secret) + " " + Redact.formEncode(secret);
        server.json(400, "{\"message\":\"" + jsonEscape(echoed) + "\",\"details\":[{\"fieldViolations\":[{\"field\":\"" + jsonEscape(secret) + "\",\"description\":\"Bearer " + jsonEscape(secret) + "\"}]}]}");
        SigningflowException.InvalidRequestException error = assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of("key", secret)).envelopes().retrieve(ENVELOPE, ""));
        String text = error.getMessage() + error.fieldViolations().get(0).field() + error.fieldViolations().get(0).description();
        assertFalse(text.contains(secret));
        assertFalse(text.contains("/b c+"));
        assertFalse(text.contains("c+"));
        assertFalse(text.contains("%2F"));
        assertTrue(error.getMessage().length() <= 501);
    }

    @Test
    void retriesIdempotentCallsAndNotUpdates() throws Exception {
        server.mode("stall", 200, "{}");
        SigningflowException.ConnectionException timed = assertThrows(SigningflowException.ConnectionException.class, () -> client(Map.of("timeout", "300", "retries", "0")).envelopes().update(ENVELOPE, Map.of("display_name", "Later")));
        assertEquals(408, timed.statusCode());
        assertEquals(1, server.hits.size());

        server.reset();
        server.json(500, "{\"message\":\"later\"}");
        server.json(500, "{\"message\":\"later\"}");
        server.json("{\"name\":\"" + ENVELOPE + "\"}");
        Envelope viewed = client(Map.of()).envelopes().retrieve(ENVELOPE, "");
        assertEquals(ENVELOPE, viewed.name());
        assertEquals(3, server.hits.size());

        server.reset();
        server.json(500, "{\"message\":\"no\"}");
        assertThrows(SigningflowException.ApiException.class, () -> client(Map.of()).envelopes().remind(ENVELOPE));
        assertEquals(1, server.hits.size());
    }

    @Test
    void responseLimitsAndRedirects() {
        server.mode("huge", 200, "{\"name\":\"" + ENVELOPE + "\"}");
        assertTrue(assertThrows(SigningflowException.ApiException.class, () -> client(Map.of()).envelopes().retrieve(ENVELOPE, "")).getMessage().contains("8 MB"));

        server.reset();
        server.mode("short", 200, "{\"name\":\"" + ENVELOPE + "\"}");
        SigningflowException.ApiException ended = assertThrows(SigningflowException.ApiException.class, () -> client(Map.of("retries", "0")).envelopes().retrieve(ENVELOPE, ""));
        assertTrue(ended.getMessage().contains("declared length"));
        assertFalse(ended.getMessage().contains(ENVELOPE));

        server.reset();
        server.mode("redirect", 302, "");
        assertThrows(SigningflowException.class, () -> client(Map.of()).envelopes().retrieve(ENVELOPE, ""));
        assertTrue(server.hits.stream().noneMatch(hit -> hit.path().equals("/secret")));

        server.reset();
        server.bytes(200, gzip("{\"name\":\"" + ENVELOPE + "\"}"), "application/json", Map.of("Content-Encoding", "gzip"));
        assertThrows(SigningflowException.ApiException.class, () -> client(Map.of()).envelopes().retrieve(ENVELOPE, ""));

        server.reset();
        server.bytes(200, "not-json".getBytes(StandardCharsets.UTF_8), "application/octet-stream", Map.of());
        assertTrue(assertThrows(SigningflowException.ApiException.class, () -> client(Map.of()).envelopes().retrieve(ENVELOPE, "")).getMessage().contains("non-JSON"));
    }

    @Test
    void uploadRetriesAndRejectsEarlyStatus() throws Exception {
        String upload = "https://127.0.0.1:" + server.port + "/bucket/a";
        server.json("{\"storages\":[{\"name\":\"" + STORAGE + "\",\"preSignedUrl\":\"" + upload + "\"}]}");
        server.json(500, "");
        server.json(200, "");
        server.json("{}");
        StoredFile stored = client(Map.of()).files().create("%PDF".getBytes(StandardCharsets.UTF_8), null, "a.pdf", "", "");
        assertEquals(STORAGE, stored.name());
        assertEquals(2, server.hits.stream().filter(hit -> "PUT".equals(hit.method())).count());

        server.reset();
        server.json("{\"storages\":[{\"name\":\"" + STORAGE + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        server.json(199, "");
        SigningflowException error = assertThrows(SigningflowException.class, () -> client(Map.of("retries", "0")).files().create(new byte[] {1}, null, "a.pdf", "application/pdf", ""));
        assertTrue(error instanceof SigningflowException.ApiException || error instanceof SigningflowException.ConnectionException);
        assertTrue(server.hits.stream().noneMatch(hit -> hit.path().contains("batchAcknowledgeUpload")));
    }

    @Test
    void sendRecoveryAndErrors() throws Exception {
        scriptDraft();
        server.json(409, "{\"message\":\"idempotency key already used\",\"metadata\":{\"resource_id\":\"" + ENVELOPE + "\"}}");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"sent_time\":\"2020-01-01T00:00:00Z\"}");
        Envelope recovered = client(Map.of()).envelopes().sendDocument("Contract", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), "");
        assertEquals(ENVELOPE, recovered.name());

        server.reset();
        scriptDraft();
        server.json(409, "{\"message\":\"conflict\"}");
        SigningflowException.InvalidRequestException conflict = assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).envelopes().sendDocument("Contract", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), ""));
        assertEquals(ENVELOPE, conflict.envelopeName());

        server.reset();
        scriptDraft();
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"sent_time\":\"2026-11-06T00:00:30Z\"}");
        assertEquals(ENVELOPE, client(Map.of()).envelopes().sendDocument("Contract", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), "").name());

        server.reset();
        scriptDraft();
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"sent_time\":\"2020-01-01T00:00:00Z\"}");
        SigningflowException.ConnectionException old = assertThrows(SigningflowException.ConnectionException.class, () -> client(Map.of()).envelopes().sendDocument("Contract", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), ""));
        assertEquals(ENVELOPE, old.envelopeName());

        server.reset();
        scriptDraft();
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"sent_time\":\"2099-01-01T00:00:00Z\"}");
        assertEquals(ENVELOPE, assertThrows(SigningflowException.ConnectionException.class, () -> client(Map.of()).envelopes().sendDocument("Contract", new byte[] {1}, null, "a.pdf", List.of(new Recipient("Ada", "ada@example.com")), "")).envelopeName());

        server.reset();
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        server.mode("drop", 0, "");
        assertThrows(SigningflowException.ConnectionException.class, () -> client(Map.of()).envelopes().send(ENVELOPE, ""));
        assertTrue(server.hits.stream().noneMatch(hit -> hit.path().contains(":view")));
    }

    @Test
    void templateListDownloadAndWebhooks() throws Exception {
        server.json("{\"envelope\":{\"uid\":\"11111111-1111-4111-8111-111111111111\",\"display_name\":\"From template\"}}");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"documents\":[{\"uid\":\"doc-1\",\"displayName\":\"From template\"}],\"compliance\":{}}");
        server.json("{\"name\":\"" + ENVELOPE + "\"}");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"sentTime\":\"2026-11-06T00:00:00Z\"}");
        Envelope fromTemplate = client(Map.of()).envelopes().sendFromTemplate(TEMPLATE, List.of(new Recipient("Ada", "ada@example.com")), "Hello");
        assertEquals(ENVELOPE, fromTemplate.name());

        server.reset();
        server.json("{\"envelopes\":[{\"name\":\"" + ENVELOPE + "\"}],\"nextPageToken\":\"abc\"}");
        server.json("{\"envelopes\":[{\"name\":\"envelopes/33333333-3333-4333-8333-333333333333\"}],\"next_page_token\":\"abc\"}");
        List<String> names = new ArrayList<>();
        client(Map.of()).envelopes().list("needAction", null, "", "name").all().forEach(item -> names.add(item.name()));
        assertEquals(List.of(ENVELOPE, "envelopes/33333333-3333-4333-8333-333333333333"), names);

        server.reset();
        server.pageForever = true;
        assertThrows(Page.TooManyPagesException.class, () -> {
            for (Envelope ignored : client(Map.of()).envelopes().list("waitingOthers", 10, null, "").all()) {
                // Walk until the page cap.
            }
        });

        server.reset();
        server.json("{\"envelopes\":[],\"nextPageToken\":\"more\"}");
        server.json(500, "{\"message\":\"page failed\"}");
        Page<Envelope> first = client(Map.of("retries", "0")).envelopes().list("needAction", 1, null, "");
        assertThrows(Page.LoadException.class, () -> {
            for (Envelope ignored : first.all()) {
                // The follow-up page fails.
            }
        });

        server.reset();
        server.json("{\"name\":\"" + ENVELOPE + "\",\"progress\":{\"state\":\"completed\"}}");
        server.json("{\"uri\":\"https://files.example/a\",\"download_time\":\"2026-11-06T00:00:00Z\",\"etag\":\"abc\"}");
        Download download = client(Map.of()).envelopes().downloadCompleted(ENVELOPE);
        assertEquals("https://files.example/a", download.uri());
        assertEquals("abc", download.etag());
        assertEquals(2, server.hits.size());

        server.reset();
        server.json("{\"name\":\"" + WEBHOOK + "\",\"displayName\":\"Hooks\",\"httpRequestUri\":\"https://example.com/hook\",\"events\":[\"DOC_ENVELOPE_COMPLETED\"],\"signingSecret\":\"whsec_once\"}");
        WebhookUrl created = client(Map.of()).webhookUrls().create("Hooks", "https://example.com/hook", List.of("DOC_ENVELOPE_COMPLETED"), null, "");
        assertEquals("whsec_once", created.signingSecret());
        server.json("{\"name\":\"" + WEBHOOK + "\",\"signing_secret\":\"whsec_hidden\",\"signingSecret\":\"whsec_hidden\"}");
        assertEquals("", client(Map.of()).webhookUrls().retrieve(WEBHOOK).signingSecret());
        server.json("{\"name\":\"" + WEBHOOK + "\",\"signingSecret\":\"whsec_test\"}");
        assertEquals("whsec_test", client(Map.of()).webhookUrls().test(WEBHOOK).signingSecret());
        server.json("{\"webhooks\":[{\"name\":\"" + DELIVERY + "\",\"event\":\"DOC_ENVELOPE_COMPLETED\"}]}");
        assertEquals(DELIVERY, client(Map.of()).webhookDeliveries().list(null, null).data().get(0).name());
        server.json("{\"name\":\"" + DELIVERY + "\",\"event\":\"DOC_ENVELOPE_COMPLETED\"}");
        assertEquals("DOC_ENVELOPE_COMPLETED", client(Map.of()).webhookDeliveries().retrieve(DELIVERY).event());
    }

    @Test
    void webhookAndInputGuards() throws Exception {
        byte[] body = "{\"event\":\"DOC_ENVELOPE_COMPLETED\"}".getBytes(StandardCharsets.UTF_8);
        String secret = "whsec_current";
        String signature = mac(secret, body);
        Event event = Webhooks.constructEvent(body, signature.toUpperCase(), secret, "", "");
        assertEquals("DOC_ENVELOPE_COMPLETED", Json.asString(Json.asMap(event.payload()).get("event")));
        assertEquals(Webhooks.bodySha256(body), event.bodySha256());
        String previous = mac("whsec_old", body);
        assertThrows(SigningflowException.SignatureVerificationException.class, () -> Webhooks.constructEvent(body, "nope", "", "whsec_old", previous));
        assertEquals(event.bodySha256(), Webhooks.constructEvent(body, "nope", secret, "whsec_old", previous).bodySha256());
        assertThrows(SigningflowException.SignatureVerificationException.class, () -> Webhooks.constructEvent(null, signature, secret, null, null));
        assertThrows(SigningflowException.SignatureVerificationException.class, () -> Webhooks.constructEvent(body, signature, "", null, null));
        assertThrows(SigningflowException.SignatureVerificationException.class, () -> Webhooks.constructEvent(body, "00", secret, "whsec_old", ""));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Webhooks.constructEvent("[".getBytes(StandardCharsets.UTF_8), mac(secret, "[".getBytes(StandardCharsets.UTF_8)), secret, null, null));

        assertTrue(assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookUrls().create("", "https://example.com", List.of("A"), null, "")).getMessage().contains("display_name"));
        assertTrue(assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookUrls().create("A", "http://example.com", List.of("A"), null, "")).getMessage().contains("https"));
        assertEquals("events is required.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookUrls().create("A", "https://example.com", List.of(), null, "")).getMessage());
        assertTrue(assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookUrls().create("A", "https://example.com", List.of("A"), Map.of("auth", "NONE"), "")).getMessage().contains("NONE"));
        assertTrue(assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).webhookUrls().create("A", "https://example.com", List.of("A"), Map.of("auth", "BASIC"), "")).getMessage().contains("HMAC"));
        assertEquals("idempotencyKey must be a UUID.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).files().create(new byte[] {1}, null, "a.pdf", "", "not-a-uuid")).getMessage());
        assertEquals("Pass file bytes or a path, not both.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).files().create(new byte[] {1}, "a.pdf", "a.pdf", "", "")).getMessage());
        assertEquals("Pass file bytes or a path.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).files().create(null, "  ", "a.pdf", "", "")).getMessage());
        assertEquals("filename is required when file is not a path.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).files().create(new byte[] {1}, null, " ", "", "")).getMessage());
        assertEquals("invalid header value", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).files().create(new byte[] {1}, null, "a.pdf", "bad\nmime", "")).getMessage());
        assertEquals("directory is required.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).envelopes().list(" ", 10, null, "")).getMessage());
        assertEquals("page_size must be from 1 to 1000.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).envelopes().list("needAction", 0, null, "")).getMessage());
        assertEquals("The signed file is not ready.", assertThrows(SigningflowException.InvalidRequestException.class, () -> {
            server.json("{\"name\":\"" + ENVELOPE + "\",\"state\":\"DRAFT\"}");
            client(Map.of()).envelopes().downloadCompleted(ENVELOPE);
        }).getMessage());
        assertEquals("Unknown operation.", assertThrows(SigningflowException.class, () -> Allowlist.operation("nope")).getMessage());
    }

    @Test
    void defaultClientRejectsTheProbeCertificate() throws Exception {
        SigningflowClient client = client(Map.of("ca", ""));
        assertThrows(SigningflowException.ConnectionException.class, () -> client.envelopes().retrieve(ENVELOPE, ""));
    }

    @Test
    void proxyListenerSeesNothing() throws Exception {
        try (ServerSocket proxy = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            proxy.setSoTimeout(200);
            System.setProperty("https.proxyHost", "127.0.0.1");
            System.setProperty("https.proxyPort", Integer.toString(proxy.getLocalPort()));
            server.json("{\"name\":\"" + ENVELOPE + "\"}");
            try {
                assertEquals(ENVELOPE, client(Map.of()).envelopes().retrieve(ENVELOPE, "").name());
                assertThrows(java.net.SocketTimeoutException.class, proxy::accept);
            } finally {
                System.clearProperty("https.proxyHost");
                System.clearProperty("https.proxyPort");
            }
        }
    }

    @Test
    void statusCodesAndRateLimitSleep() throws Exception {
        server.json(401, "{\"message\":\"no\",\"code\":16}");
        assertInstanceOf(SigningflowException.AuthenticationException.class, assertThrows(SigningflowException.class, () -> client(Map.of()).envelopes().retrieve(ENVELOPE, "")));
        server.json(403, "{\"message\":\"no\"}");
        assertInstanceOf(SigningflowException.PermissionException.class, assertThrows(SigningflowException.class, () -> client(Map.of()).envelopes().retrieve(ENVELOPE, "")));
        server.json(429, "{\"message\":\"slow\"}");
        server.json(429, "{\"message\":\"slow\"}");
        server.json("{\"name\":\"" + ENVELOPE + "\"}");
        List<Duration> slept = new ArrayList<>();
        Clock.sleep = slept::add;
        Clock.now = () -> NOW;
        assertEquals(ENVELOPE, client(Map.of()).envelopes().retrieve(ENVELOPE, "").name());
        server.reset();
        server.bytes(429, "{\"message\":\"slow\"}".getBytes(StandardCharsets.UTF_8), "application/json", Map.of("Rate-Limit-Retry-After", "2099-01-01T00:00:00Z"));
        server.json("{\"name\":\"" + ENVELOPE + "\"}");
        slept.clear();
        client(Map.of("retries", "1")).envelopes().retrieve(ENVELOPE, "");
        assertEquals(Duration.ofSeconds(60), slept.get(0));
        assertEquals(60, Urls.retryDelay("2099-01-01T00:00:00Z", "", NOW).getSeconds());
        assertEquals(0, Urls.retryDelay("2", "", NOW).getSeconds());
        assertNull(Urls.parseTime("not-a-time"));
    }

    @Test
    @Timeout(3)
    void jailRefusesLinksAndReadsARegularFile() throws Exception {
        Path root = Files.createTempDirectory("signingflow-jail");
        Path secret = Files.createTempDirectory("signingflow-secret");
        try {
            Files.writeString(root.resolve("doc.pdf"), "%PDF");
            assertArrayEquals("%PDF".getBytes(StandardCharsets.UTF_8), Jail.read(root.toString(), "doc.pdf"));
            Files.write(root.resolve("empty.pdf"), new byte[0]);
            assertEquals(0, Jail.read(root.toString(), "empty.pdf").length);
            Files.write(root.resolve("big.bin"), new byte[] {1, 2});
            assertEquals("The file is larger than 25 MB.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "big.bin", 1)).getMessage());
            assertEquals("A filesystem path requires upload_root.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(" ", "doc.pdf")).getMessage());
            assertEquals("The path is outside upload_root.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "/etc/passwd")).getMessage());
            assertEquals("The path is outside upload_root.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "../doc.pdf")).getMessage());
            assertEquals("The path is outside upload_root.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "")).getMessage());
            Files.createSymbolicLink(root.resolve("link.pdf"), root.resolve("doc.pdf"));
            assertEquals("The file could not be read.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "link.pdf")).getMessage());
            Files.createLink(root.resolve("hard.pdf"), root.resolve("doc.pdf"));
            assertEquals("The file must not be a hard link.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "doc.pdf")).getMessage());
            Files.writeString(secret.resolve("outside.txt"), "secret");
            Files.createSymbolicLink(root.resolve("out"), secret);
            assertEquals("The path is outside upload_root.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "out/outside.txt")).getMessage());
            Path fifo = root.resolve("fifo");
            assertEquals(0, new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor());
            assertEquals("The file could not be read.", assertThrows(SigningflowException.InvalidRequestException.class, () -> Jail.read(root.toString(), "fifo")).getMessage());
            String upload = "https://127.0.0.1:" + server.port + "/bucket/a";
            server.json("{\"storages\":[{\"name\":\"" + STORAGE + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
            server.json(200, "");
            server.json("{}");
            StoredFile stored = client(Map.of("root", root.toString())).files().create(null, "empty.pdf", "", "text/plain", "11111111-1111-4111-8111-111111111111");
            assertEquals(STORAGE, stored.name());
            assertTrue(server.hits.get(0).text().contains("\"size\":\"0\""));
        } finally {
            deleteTree(root);
            deleteTree(secret);
        }
    }

    @Test
    void jsonUrlsAndUploadHosts() throws Exception {
        Map<String, Object> decoded = Json.asMap(Json.read("{\"n\":1,\"f\":1.5,\"ok\":true,\"no\":null,\"s\":\"a\\nb\",\"list\":[1]}"));
        assertEquals(1, Json.asInt(decoded.get("n")));
        assertEquals(1, Json.asInt(decoded.get("f")));
        assertNull(Json.asInt(decoded.get("ok")));
        assertNull(Json.asInt(Boolean.FALSE));
        assertEquals("", Json.asString(1));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("{"));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read("{\"a\":1} trailing"));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Json.write(Double.NaN));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Json.write(new Object()));
        StringBuilder deep = new StringBuilder();
        deep.append("{\"a\":".repeat(40)).append("1").append("}".repeat(40));
        assertThrows(SigningflowException.ApiException.class, () -> Json.read(deep.toString()));
        assertEquals("https://api.signingflow.com/v1/envelopes/abc", Urls.resolve("https://api.signingflow.com", "/v1/envelopes/abc", Map.of("pageToken", "")));
        assertEquals("[::1]", Urls.hostOf(URI.create("https://[::1]/v1")));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.allowedUploadUrl("http://storage.googleapis.com/a", List.of("storage.googleapis.com")));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.allowedUploadUrl("https://user@storage.googleapis.com/a", List.of("storage.googleapis.com")));
        assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.allowedUploadUrl("https://evil.com/a", List.of("storage.googleapis.com")));
        URI allowed = Urls.allowedUploadUrl("https://bucket.storage.googleapis.com/a#@evil.com", List.of("storage.googleapis.com"));
        assertEquals("bucket.storage.googleapis.com", allowed.getHost());
        assertEquals("upload host rejected", assertThrows(SigningflowException.InvalidRequestException.class, () -> Urls.allowedUploadUrl("https://notstorage.googleapis.com/a", List.of("storage.googleapis.com"))).getMessage());
        assertTrue(Redact.message("x".repeat(600), "").endsWith("…"));
        assertEquals("df_sk_redacted", Redact.text("df_sk_plain", ""));
        Envelope prepared = prepareOnly();
        assertEquals(ENVELOPE, prepared.name());
        assertEquals("Name the draft title.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).envelopes().create(" ", "", STORAGE, "")).getMessage());
        assertEquals("Each recipient needs a name and an email.", assertThrows(SigningflowException.InvalidRequestException.class, () -> client(Map.of()).envelopes().sendDocument("Title", new byte[] {1}, null, "a.pdf", List.of(new Recipient("", "ada@example.com")), "")).getMessage());
    }

    private Envelope prepareOnly() throws Exception {
        String upload = "https://127.0.0.1:" + server.port + "/bucket/a";
        server.json("{\"storages\":[{\"name\":\"" + STORAGE + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        server.json(200, "");
        server.json("{}");
        server.json("{\"name\":\"" + ENVELOPE + "\",\"display_name\":\"Draft\"}");
        return client(Map.of()).envelopes().prepareDraft("Draft", new byte[] {1}, null, "draft.pdf", "note");
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
        String key = (String) overrides.getOrDefault("key", "df_sk_test");
        String workspace = (String) overrides.getOrDefault("workspace", "ws");
        String base = (String) overrides.getOrDefault("base", "https://127.0.0.1:" + server.port);
        boolean custom = overrides.containsKey("custom")
                ? Boolean.TRUE.equals(overrides.get("custom"))
                : !base.toLowerCase(java.util.Locale.ROOT).contains("api.signingflow.com");
        return new SigningflowClient(key, ClientOptions.builder()
                .workspaceId(workspace)
                .env((String) overrides.getOrDefault("env", "sandbox"))
                .baseUrl(base)
                .allowCustomBaseUrl(custom)
                .timeout(Duration.ofMillis(Long.parseLong(String.valueOf(overrides.getOrDefault("timeout", "2000")))))
                .maxNetworkRetries(Integer.parseInt(String.valueOf(overrides.getOrDefault("retries", "2"))))
                .uploadHosts(hosts(overrides))
                .channel((String) overrides.getOrDefault("channel", ""))
                .funnel((String) overrides.getOrDefault("funnel", ""))
                .uploadRoot((String) overrides.getOrDefault("root", ""))
                .caBundle((String) overrides.getOrDefault("ca", server.certificate.toString()))
                .build());
    }

    @SuppressWarnings("unchecked")
    private static List<String> hosts(Map<String, Object> overrides) {
        if (overrides.containsKey("hosts")) {
            return (List<String>) overrides.get("hosts");
        }
        return List.of("127.0.0.1");
    }

    private static byte[] gzip(String text) {
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
                gzip.write(text.getBytes(StandardCharsets.UTF_8));
            }
            return out.toByteArray();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static String mac(String secret, byte[] body) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        StringBuilder hex = new StringBuilder();
        for (byte bite : hmac.doFinal(body)) {
            hex.append(String.format("%02x", bite));
        }
        return hex.toString();
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) {
            return;
        }
        try (var walk = Files.walk(root)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                    // Best-effort cleanup of the fixture directory.
                }
            });
        }
    }
}
