package com.signingflow;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class Values {
    private Values() {}

    static String first(Object record, String... keys) {
        Map<String, Object> map = Json.asMap(record);
        if (map == null) {
            return "";
        }
        for (String key : keys) {
            String value = Json.asString(map.get(key));
            if (!value.isEmpty()) {
                return value;
            }
        }
        return "";
    }

    static Integer grpcCode(Object body) {
        Map<String, Object> record = Json.asMap(body);
        if (record == null) {
            return null;
        }
        return Json.asInt(record.get("code"));
    }

    static String serverMessage(Object body) {
        if (body instanceof String text) {
            return text;
        }
        Map<String, Object> record = Json.asMap(body);
        if (record == null) {
            return "";
        }
        return Json.asString(record.get("message"));
    }

    static String traceCode(Object body) {
        return findMeta(body, "trace_code");
    }

    static String resourceName(Object body) {
        String url = findMeta(body, "resource_url");
        if (!url.isEmpty()) {
            return url;
        }
        return findMeta(body, "resource_id");
    }

    static List<SigningflowException.FieldViolation> fieldViolations(Object body) {
        List<SigningflowException.FieldViolation> found = new ArrayList<>();
        walk(body, record -> {
            Object items = record.get("fieldViolations");
            if (!(items instanceof List<?>)) {
                items = record.get("field_violations");
            }
            if (!(items instanceof List<?> list)) {
                return;
            }
            for (Object item : list) {
                Map<String, Object> row = Json.asMap(item);
                if (row == null) {
                    continue;
                }
                String field = Json.asString(row.get("field"));
                String description = Json.asString(row.get("description"));
                if (!field.isEmpty() || !description.isEmpty()) {
                    found.add(new SigningflowException.FieldViolation(field, description));
                }
            }
        });
        return found;
    }

    static boolean mentionsIdempotency(Object body) {
        try {
            String encoded = Json.write(body).toLowerCase(Locale.ROOT);
            return encoded.contains("idempotency");
        } catch (SigningflowException ex) {
            return false;
        }
    }

    private static String findMeta(Object body, String key) {
        String[] found = {""};
        walk(body, record -> {
            if (!found[0].isEmpty()) {
                return;
            }
            Map<String, Object> meta = Json.asMap(record.get("metadata"));
            if (meta == null) {
                return;
            }
            String value = Json.asString(meta.get(key));
            if (!value.isEmpty()) {
                found[0] = value;
            }
        });
        return found[0];
    }

    private static void walk(Object value, Visitor visitor) {
        Map<String, Object> map = Json.asMap(value);
        if (map != null) {
            visitor.visit(map);
            for (Object child : map.values()) {
                walk(child, visitor);
            }
            return;
        }
        if (value instanceof List<?> list) {
            for (Object child : list) {
                walk(child, visitor);
            }
        }
    }

    private interface Visitor {
        void visit(Map<String, Object> record);
    }
}
