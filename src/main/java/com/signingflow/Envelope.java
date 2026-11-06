package com.signingflow;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class Envelope {
    private String name;
    private final String uid;
    private final String displayName;
    private final String description;
    private final String progressStatus;
    private final String state;
    private final String condition;
    private final String sentTime;
    private final List<Map<String, Object>> documents;
    private final Map<String, Object> compliance;
    private final Map<String, Object> progress;

    Envelope(String name, String uid, String displayName, String description, String progressStatus, String state, String condition, String sentTime, List<Map<String, Object>> documents, Map<String, Object> compliance, Map<String, Object> progress) {
        this.name = name;
        this.uid = uid;
        this.displayName = displayName;
        this.description = description;
        this.progressStatus = progressStatus;
        this.state = state;
        this.condition = condition;
        this.sentTime = sentTime;
        this.documents = documents;
        this.compliance = compliance;
        this.progress = progress;
    }

    public String name() { return name; }
    public String uid() { return uid; }
    public String displayName() { return displayName; }
    public String description() { return description; }
    public String sentTime() { return sentTime; }
    public List<Map<String, Object>> documents() { return documents; }
    public Map<String, Object> compliance() { return compliance; }

    void name(String value) { this.name = value; }

    String stateValue() {
        if (progress != null) {
            String nested = Json.asString(progress.get("state"));
            if (!nested.isEmpty()) {
                return nested;
            }
        }
        if (!progressStatus.isEmpty()) {
            return progressStatus;
        }
        if (!state.isEmpty()) {
            return state;
        }
        return condition;
    }
}

final class Models {
    private static final java.util.regex.Pattern ENVELOPE = java.util.regex.Pattern.compile("^envelopes/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern TEMPLATE = java.util.regex.Pattern.compile("^templates/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern WEBHOOK = java.util.regex.Pattern.compile("^webhookUrls/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern DELIVERY = java.util.regex.Pattern.compile("^webhooks/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern STORAGE = java.util.regex.Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern EMAIL = java.util.regex.Pattern.compile("^[^\\s@]+@[^\\s@]+$");

    private Models() {}

    static String envelopeName(String name) throws SigningflowException.InvalidRequestException {
        String value = name == null ? "" : name.trim();
        if (!ENVELOPE.matcher(value).matches()) {
            throw new SigningflowException.InvalidRequestException("envelope must look like envelopes/{id}.");
        }
        return value;
    }

    static String templateName(String name) throws SigningflowException.InvalidRequestException {
        String value = name == null ? "" : name.trim();
        if (!TEMPLATE.matcher(value).matches()) {
            throw new SigningflowException.InvalidRequestException("template must look like templates/{id}.");
        }
        return value;
    }

    static String webhookName(String name) throws SigningflowException.InvalidRequestException {
        String value = name == null ? "" : name.trim();
        if (!WEBHOOK.matcher(value).matches()) {
            throw new SigningflowException.InvalidRequestException("webhook url must look like webhookUrls/{id}.");
        }
        return value;
    }

    static String deliveryName(String name) throws SigningflowException.InvalidRequestException {
        String value = name == null ? "" : name.trim();
        if (!DELIVERY.matcher(value).matches()) {
            throw new SigningflowException.InvalidRequestException("webhook delivery must look like webhooks/{id}.");
        }
        return value;
    }

    static List<Recipient> cleanRecipients(List<Recipient> recipients) throws SigningflowException.InvalidRequestException {
        if (recipients == null || recipients.isEmpty()) {
            throw new SigningflowException.InvalidRequestException("Each recipient needs a name and an email.");
        }
        List<Recipient> people = new ArrayList<>();
        for (Recipient person : recipients) {
            String personName = person == null || person.name() == null ? "" : person.name().trim();
            String email = person == null || person.email() == null ? "" : person.email().trim();
            if (personName.isEmpty() || !EMAIL.matcher(email).matches()) {
                throw new SigningflowException.InvalidRequestException("Each recipient needs a name and an email.");
            }
            people.add(new Recipient(personName, email));
        }
        return people;
    }

    static Envelope decode(Object body) {
        Map<String, Object> record = Json.asMap(body);
        if (record == null) {
            record = Map.of();
        }
        Map<String, Object> nested = Json.asMap(record.get("envelope"));
        if (nested != null) {
            record = nested;
        }
        List<Map<String, Object>> documents = new ArrayList<>();
        if (record.get("documents") instanceof List<?> raw) {
            for (Object item : raw) {
                Map<String, Object> doc = Json.asMap(item);
                if (doc != null) {
                    documents.add(doc);
                }
            }
        }
        return new Envelope(
                Json.asString(record.get("name")),
                Json.asString(record.get("uid")),
                Values.first(record, "display_name", "displayName"),
                Json.asString(record.get("description")),
                Values.first(record, "progress_status", "progressStatus"),
                Json.asString(record.get("state")),
                Json.asString(record.get("condition")),
                Values.first(record, "sent_time", "sentTime"),
                documents,
                Json.asMap(record.get("compliance")),
                Json.asMap(record.get("progress")));
    }

    static String nameOf(Object body) {
        Map<String, Object> record = Json.asMap(body);
        if (record == null) {
            record = Map.of();
        }
        Map<String, Object> nested = Json.asMap(record.get("envelope"));
        if (nested == null) {
            nested = Map.of();
        }
        String name = Json.asString(nested.get("name"));
        if (name.isEmpty()) {
            name = Json.asString(record.get("name"));
        }
        if (name.startsWith("envelopes/")) {
            return name;
        }
        String uid = Json.asString(nested.get("uid"));
        if (uid.isEmpty()) {
            uid = Json.asString(record.get("uid"));
        }
        return uid.isEmpty() ? "" : "envelopes/" + uid;
    }

    static Envelope created(Object body) {
        Envelope envelope = decode(body);
        String name = nameOf(body);
        if (!name.isEmpty()) {
            envelope.name(name);
        } else if (envelope.name().isEmpty() && !envelope.uid().isEmpty()) {
            envelope.name("envelopes/" + envelope.uid());
        }
        return envelope;
    }

    static String[] findStorage(Object body) {
        Map<String, Object> record = Json.asMap(body);
        if (record != null && record.containsKey("storages")) {
            String[] found = findStorage(record.get("storages"));
            if (found != null) {
                return found;
            }
        }
        return walkStorage(body);
    }

    private static String[] walkStorage(Object body) {
        Map<String, Object> map = Json.asMap(body);
        if (map != null) {
            String rawUrl = Values.first(map, "pre_signed_url", "preSignedUrl");
            String name = Json.asString(map.get("name"));
            String fileId = name.contains("/") ? name.substring(name.lastIndexOf('/') + 1) : name;
            if (name.startsWith("storages/") && STORAGE.matcher(fileId).matches() && !rawUrl.isEmpty()) {
                return new String[] {name, fileId, rawUrl};
            }
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if ("storages".equals(entry.getKey())) {
                    continue;
                }
                String[] found = walkStorage(entry.getValue());
                if (found != null) {
                    return found;
                }
            }
            return null;
        }
        if (body instanceof List<?> list) {
            for (Object child : list) {
                String[] found = walkStorage(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
