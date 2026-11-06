package com.signingflow;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Envelopes {
    private final Transport transport;
    private final Files files;
    private final Templates templates;

    Envelopes(Transport transport, Files files, Templates templates) {
        this.transport = transport;
        this.files = files;
        this.templates = templates;
    }

    public Envelope create(String displayName, String description, String storageId, String idempotencyKey) throws SigningflowException {
        String title = displayName == null ? "" : displayName.trim();
        if (title.isEmpty()) {
            throw new SigningflowException.InvalidRequestException("Name the draft title.");
        }
        String storage = storageId == null ? "" : storageId.trim();
        if (storage.isEmpty()) {
            throw new SigningflowException.InvalidRequestException("storage_id is required.");
        }
        Map<String, Object> attachment = new LinkedHashMap<>();
        attachment.put("storage_id", storage);
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("display_name", title);
        document.put("attachments", List.of(attachment));
        document.put("supplemental", false);
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("display_name", title);
        envelope.put("description", description == null ? "" : description.trim());
        envelope.put("documents", List.of(document));
        Map<String, Object> created = transport.call("EnvelopeService_AddEnvelope", Map.of(), Map.of(), Map.of("envelope", envelope), idempotencyKey);
        return Models.created(created);
    }

    public Envelope retrieve(String name, String readMask) throws SigningflowException {
        String envelope = Models.envelopeName(name);
        Map<String, Object> viewed = transport.call("EnvelopeService_ViewEnvelope", Map.of("name", envelope), Map.of("readMask", readMask == null ? "" : readMask), null, "");
        Envelope decoded = Models.decode(viewed);
        if (decoded.name().isEmpty()) {
            decoded.name(envelope);
        }
        return decoded;
    }

    public Envelope update(String name, Map<String, Object> body) throws SigningflowException {
        String envelope = Models.envelopeName(name);
        Map<String, Object> payload = new LinkedHashMap<>();
        if (body != null) {
            payload.putAll(body);
        }
        if (Json.asString(payload.get("name")).isEmpty()) {
            payload.put("name", envelope);
        }
        Map<String, Object> updated = transport.call("EnvelopeService_UpdateEnvelope", Map.of("name", envelope), Map.of(), payload, "");
        return Models.decode(updated);
    }

    public Envelope send(String name, String idempotencyKey) throws SigningflowException {
        String envelope = Models.envelopeName(name);
        Map<String, Object> sent = transport.call("EnvelopeService_SendEnvelope", Map.of("name", envelope), Map.of(), Map.of(), idempotencyKey);
        Envelope decoded = Models.decode(sent);
        if (decoded.name().isEmpty()) {
            decoded.name(envelope);
        }
        return decoded;
    }

    public Page<Envelope> list(String directory, Integer pageSize, String pageToken, String readMask) throws SigningflowException {
        String folder = directory == null ? "" : directory.trim();
        if (folder.isEmpty()) {
            throw new SigningflowException.InvalidRequestException("directory is required.");
        }
        int size = Page.pageSize(pageSize);
        String mask = readMask == null ? "" : readMask;
        Page.Loader<Envelope> load = token -> listPage(folder, size, token, mask);
        Page<Envelope> page = load.load(pageToken == null ? "" : pageToken);
        return new Page<>(page.data(), page.nextPageToken(), load);
    }

    public Envelope remind(String name) throws SigningflowException {
        String envelope = Models.envelopeName(name);
        Map<String, Object> reminded = transport.call("EnvelopeService_RemindEnvelopeSigners", Map.of("name", envelope), Map.of(), Map.of(), "");
        Envelope decoded = Models.decode(reminded);
        if (decoded.name().isEmpty()) {
            decoded.name(envelope);
        }
        return decoded;
    }

    public Download download(String name) throws SigningflowException {
        String envelope = Models.envelopeName(name);
        Map<String, Object> downloaded = transport.call("EnvelopeService_DownloadEnvelope", Map.of("name", envelope), Map.of(), null, "");
        return new Download(Json.asString(downloaded.get("uri")), Values.first(downloaded, "download_time", "downloadTime"), Json.asString(downloaded.get("etag")));
    }

    public Envelope prepareDraft(String title, byte[] file, String path, String filename, String message) throws SigningflowException {
        String name = title == null ? "" : title.trim();
        if (name.isEmpty()) {
            throw new SigningflowException.InvalidRequestException("Name the PDF and the draft title.");
        }
        StoredFile stored = files.create(file, path, filename, "", "");
        return create(name, message, stored.id(), "");
    }

    public Envelope sendDocument(String title, byte[] file, String path, String filename, List<Recipient> recipients, String message) throws SigningflowException {
        String name = title == null ? "" : title.trim();
        if (name.isEmpty()) {
            throw new SigningflowException.InvalidRequestException("Name the PDF, the title, and the recipients.");
        }
        List<Recipient> people = Models.cleanRecipients(recipients);
        StoredFile stored = files.create(file, path, filename, "", "");
        Envelope created = create(name, message, stored.id(), "");
        return finishSend(created, people, message, name);
    }

    public Envelope sendFromTemplate(String template, List<Recipient> recipients, String message) throws SigningflowException {
        List<Recipient> people = Models.cleanRecipients(recipients);
        Envelope created = templates.use(template, "");
        return finishSend(created, people, message, template);
    }

    public Download downloadCompleted(String name) throws SigningflowException {
        String envelope = Models.envelopeName(name);
        Envelope viewed = retrieve(envelope, "");
        if (!"COMPLETED".equals(viewed.stateValue().trim().toUpperCase(java.util.Locale.ROOT))) {
            throw new SigningflowException.InvalidRequestException("The signed file is not ready.").attach(envelope);
        }
        return download(envelope);
    }

    private Page<Envelope> listPage(String directory, int pageSize, String pageToken, String readMask) throws SigningflowException {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("directory", directory);
        query.put("pageSize", Integer.toString(pageSize));
        query.put("pageToken", pageToken);
        query.put("readMask", readMask);
        Map<String, Object> body = transport.call("EnvelopeService_ListEnvelopes", Map.of("parent", "envelopes"), query, null, "");
        List<Envelope> data = new ArrayList<>();
        for (Object item : Page.items(body, "envelopes")) {
            data.add(Models.decode(item));
        }
        return new Page<>(data, Page.nextToken(body), null);
    }

    private Envelope finishSend(Envelope created, List<Recipient> people, String message, String label) throws SigningflowException {
        String name = created.name();
        try {
            Models.envelopeName(name);
        } catch (SigningflowException ex) {
            throw new SigningflowException.ApiException(label + " was saved without an envelope name.");
        }
        Envelope viewed;
        try {
            viewed = retrieve(name, "documents,compliance");
        } catch (SigningflowException ex) {
            throw ex.attach(name);
        }
        Map<String, Object> patched = withRecipients(viewed, people, message);
        if (patched == null) {
            throw new SigningflowException.InvalidRequestException("The draft has no document to address.").attach(name);
        }
        try {
            update(name, patched);
        } catch (SigningflowException ex) {
            throw ex.attach(name);
        }
        return sendOrView(name);
    }

    private Envelope sendOrView(String name) throws SigningflowException {
        Instant started = Clock.instant();
        try {
            return send(name, "");
        } catch (SigningflowException.IdempotencyException error) {
            if (name.equals(error.resourceName())) {
                try {
                    return retrieve(name, "");
                } catch (SigningflowException ex) {
                    throw error.attach(name);
                }
            }
            throw error.attach(name);
        } catch (SigningflowException.ConnectionException error) {
            try {
                Envelope viewed = retrieve(name, "");
                Instant sent = Urls.parseTime(viewed.sentTime());
                if (sent != null && sentDuring(sent, started, Clock.instant())) {
                    return viewed;
                }
            } catch (SigningflowException ex) {
                throw error.attach(name);
            }
            throw error.attach(name);
        } catch (SigningflowException error) {
            throw error.attach(name);
        }
    }

    private Map<String, Object> withRecipients(Envelope envelope, List<Recipient> people, String message) {
        List<Map<String, String>> refs = new ArrayList<>();
        for (Map<String, Object> item : envelope.documents()) {
            String uid = Values.first(item, "uid", "id");
            if (uid.isEmpty()) {
                continue;
            }
            refs.add(Map.of("uid", uid, "display_name", Values.first(item, "display_name", "displayName")));
        }
        if (refs.isEmpty()) {
            return null;
        }
        List<Map<String, Object>> participants = new ArrayList<>();
        int index = 0;
        for (Recipient person : people) {
            Map<String, Object> participant = new LinkedHashMap<>();
            participant.put("uid", Transport.uuid4());
            participant.put("display_name", person.name());
            participant.put("alternate_email", person.email());
            participant.put("role", "SIGNER");
            participant.put("type", "PERSONAL");
            participant.put("action_order_type", "SERIAL");
            participant.put("action_order_number", index + 1);
            participants.add(participant);
            index++;
        }
        String profile = "STANDARD";
        if (envelope.compliance() != null && !Json.asString(envelope.compliance().get("profile")).isEmpty()) {
            profile = Json.asString(envelope.compliance().get("profile"));
        }
        String description = message != null && !message.isBlank() ? message.trim() : envelope.description();
        List<Map<String, Object>> documents = new ArrayList<>();
        for (int i = 0; i < refs.size(); i++) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("uid", refs.get(i).get("uid"));
            item.put("display_name", refs.get(i).get("display_name"));
            if (i == 0) {
                item.put("participants", participants);
            }
            documents.add(item);
        }
        Map<String, Object> patched = new LinkedHashMap<>();
        patched.put("name", envelope.name());
        patched.put("display_name", envelope.displayName());
        patched.put("description", description);
        patched.put("compliance", Map.of("profile", profile));
        patched.put("documents", documents);
        return patched;
    }

    private static boolean sentDuring(Instant sent, Instant started, Instant current) {
        return !sent.isBefore(started)
                && !sent.isAfter(started.plusSeconds(120))
                && !sent.isAfter(current.plusSeconds(60));
    }
}
