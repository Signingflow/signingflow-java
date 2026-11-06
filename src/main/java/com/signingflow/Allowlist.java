package com.signingflow;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Allowlist {
    private static Map<String, Operation> byId;

    private Allowlist() {}

    public static Operation operation(String id) throws SigningflowException {
        Operation found = load().get(id);
        if (found == null) {
            throw new SigningflowException("Unknown operation.");
        }
        return found;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Operation> load() throws SigningflowException {
        if (byId != null) {
            return byId;
        }
        try (InputStream in = Allowlist.class.getResourceAsStream("/allowlist.json")) {
            if (in == null) {
                throw new IllegalStateException("The allowlist could not be read.");
            }
            Object decoded = Json.read(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            Map<String, Object> root = Json.asMap(decoded);
            Object rawOps = root == null ? null : root.get("operations");
            if (!(rawOps instanceof List<?> operations) || operations.size() != 15) {
                throw new IllegalStateException("The allowlist is invalid.");
            }
            Map<String, Operation> loaded = new LinkedHashMap<>();
            for (Object item : operations) {
                Map<String, Object> row = Json.asMap(item);
                if (row == null) {
                    throw new IllegalStateException("The allowlist is invalid.");
                }
                String id = Json.asString(row.get("operationId"));
                if (id.isEmpty() || loaded.containsKey(id)) {
                    throw new IllegalStateException("The allowlist is invalid.");
                }
                loaded.put(id, new Operation(
                        id,
                        Json.asString(row.get("http")),
                        Json.asString(row.get("path")),
                        Boolean.TRUE.equals(row.get("idempotent")),
                        Json.asString(row.get("capability"))));
            }
            byId = Map.copyOf(loaded);
            return byId;
        } catch (IOException | SigningflowException.ApiException ex) {
            throw new IllegalStateException("The allowlist is invalid.");
        }
    }

    public record Operation(String id, String http, String path, boolean idempotent, String capability) {}
}
