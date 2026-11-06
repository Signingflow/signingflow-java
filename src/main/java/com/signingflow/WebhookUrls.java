package com.signingflow;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class WebhookUrls {
    private final Transport transport;

    WebhookUrls(Transport transport) {
        this.transport = transport;
    }

    public WebhookUrl create(String displayName, String httpRequestUri, List<String> events, Object httpConfig, String idempotencyKey) throws SigningflowException {
        String name = displayName == null ? "" : displayName.trim();
        if (name.isEmpty() || name.length() > 100) {
            throw new SigningflowException.InvalidRequestException("display_name must be 1 to 100 characters.");
        }
        URI uri;
        try {
            uri = URI.create(httpRequestUri == null ? "" : httpRequestUri);
        } catch (IllegalArgumentException ex) {
            throw new SigningflowException.InvalidRequestException("http_request_uri must be an https URL.");
        }
        if (uri.getHost() == null || !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new SigningflowException.InvalidRequestException("http_request_uri must be an https URL.");
        }
        if (events == null || events.isEmpty()) {
            throw new SigningflowException.InvalidRequestException("events is required.");
        }
        if (httpConfig != null) {
            String auth = "";
            if (httpConfig instanceof Map<?, ?> map) {
                Object value = map.get("auth");
                auth = value == null ? "" : value.toString();
            } else {
                auth = httpConfig.toString();
            }
            if ("NONE".equals(auth.toUpperCase(Locale.ROOT))) {
                throw new SigningflowException.InvalidRequestException("auth NONE has no signature. Leave http_config empty.");
            }
            throw new SigningflowException.InvalidRequestException("Leave http_config empty so the destination uses HMAC.");
        }
        Map<String, Object> webhook = new LinkedHashMap<>();
        webhook.put("displayName", name);
        webhook.put("httpRequestUri", httpRequestUri);
        webhook.put("events", new ArrayList<>(events));
        Map<String, Object> created = transport.call("WebhookUrlService_AddWebhookUrl", Map.of(), Map.of(), Map.of("webhookUrl", webhook), idempotencyKey);
        return decode(created, false);
    }

    public WebhookUrl retrieve(String name) throws SigningflowException {
        String destination = Models.webhookName(name);
        Map<String, Object> viewed = transport.call("WebhookUrlService_ViewWebhookUrl", Map.of("name", destination), Map.of(), null, "");
        return decode(viewed, true);
    }

    public WebhookUrl test(String name) throws SigningflowException {
        String destination = Models.webhookName(name);
        Map<String, Object> tested = transport.call("WebhookUrlService_TestWebhookUrl", Map.of("name", destination), Map.of(), Map.of(), "");
        return decode(tested, false);
    }

    public static String signingSecretOf(Object body) {
        if (body instanceof WebhookUrl url) {
            return url.signingSecret();
        }
        Map<String, Object> record = Json.asMap(body);
        if (record == null) {
            return "";
        }
        String secret = Json.asString(record.get("signing_secret"));
        if (!secret.isEmpty()) {
            return secret;
        }
        return Json.asString(record.get("signingSecret"));
    }

    private static WebhookUrl decode(Object body, boolean dropSecret) {
        Map<String, Object> record = Json.asMap(body);
        if (record == null) {
            record = Map.of();
        } else {
            record = new LinkedHashMap<>(record);
        }
        if (dropSecret) {
            record.remove("signing_secret");
            record.remove("signingSecret");
        }
        List<String> events = new ArrayList<>();
        if (record.get("events") instanceof List<?> raw) {
            for (Object event : raw) {
                String text = Json.asString(event);
                if (!text.isEmpty()) {
                    events.add(text);
                }
            }
        }
        return new WebhookUrl(
                Json.asString(record.get("name")),
                Values.first(record, "displayName", "display_name"),
                Values.first(record, "httpRequestUri", "http_request_uri"),
                events,
                signingSecretOf(record));
    }
}
