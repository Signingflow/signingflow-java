package com.signingflow;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class Files {
    private static final int MAX_BYTES = 25 * 1024 * 1024;
    private static final Map<String, String> MIME = Map.of(
            "pdf", "application/pdf",
            "png", "image/png",
            "jpg", "image/jpeg",
            "jpeg", "image/jpeg",
            "txt", "text/plain",
            "json", "application/json");

    private final Transport transport;

    Files(Transport transport) {
        this.transport = transport;
    }

    public StoredFile create(byte[] file, String path, String filename, String mimeType, String idempotencyKey) throws SigningflowException {
        Loaded loaded = load(file, path, filename, mimeType);
        Map<String, Object> storage = new LinkedHashMap<>();
        storage.put("originalName", loaded.filename);
        storage.put("displayName", loaded.filename);
        storage.put("size", Integer.toString(loaded.data.length));
        storage.put("extension", loaded.extension);
        storage.put("mimeType", loaded.mime);
        Map<String, Object> added = transport.call(
                "StorageService_BatchAddStorage",
                Map.of(),
                Map.of(),
                Map.of("storages", List.of(storage)),
                idempotencyKey);
        String[] found = Models.findStorage(added);
        if (found == null) {
            throw new SigningflowException.ApiException("Storage did not return an upload URL.");
        }
        var upload = Urls.allowedUploadUrl(found[2], transport.options().uploadHosts());
        transport.putBytes(upload, loaded.mime, loaded.data);
        transport.call("StorageService_BatchAcknowledgeUpload", Map.of(), Map.of(), Map.of("names", List.of(found[0])), "");
        return new StoredFile(found[0], found[1]);
    }

    private Loaded load(byte[] file, String path, String filename, String mimeType) throws SigningflowException.InvalidRequestException {
        boolean hasFile = file != null;
        String requested = path == null ? "" : path.trim();
        boolean hasPath = !requested.isEmpty();
        if (hasFile && hasPath) {
            throw new SigningflowException.InvalidRequestException("Pass file bytes or a path, not both.");
        }
        if (!hasFile && !hasPath) {
            throw new SigningflowException.InvalidRequestException("Pass file bytes or a path.");
        }
        byte[] data = hasFile ? file : Jail.read(transport.options().uploadRoot(), requested);
        if (data.length > MAX_BYTES) {
            throw new SigningflowException.InvalidRequestException("The file is larger than 25 MB.");
        }
        String name = filename == null ? "" : filename.trim();
        if (name.isEmpty() && hasPath) {
            int slash = Math.max(requested.lastIndexOf('/'), requested.lastIndexOf('\\'));
            name = slash < 0 ? requested : requested.substring(slash + 1);
        }
        if (name.isEmpty() || ".".equals(name) || "/".equals(name)) {
            throw new SigningflowException.InvalidRequestException("filename is required when file is not a path.");
        }
        int dot = name.lastIndexOf('.');
        String extension = dot < 0 ? "" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
        String mime = mimeType == null ? "" : mimeType.trim();
        if (mime.isEmpty()) {
            mime = MIME.getOrDefault(extension, "");
        }
        if (mime.isEmpty()) {
            mime = "application/octet-stream";
        }
        if (ClientOptions.badHeader(mime)) {
            throw new SigningflowException.InvalidRequestException("invalid header value");
        }
        return new Loaded(data, name, extension, mime);
    }

    private record Loaded(byte[] data, String filename, String extension, String mime) {}
}
