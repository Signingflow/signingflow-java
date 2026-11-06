package com.signingflow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A small JSON reader and writer for the allowlist payloads. */
public final class Json {
    private static final int MAX_DEPTH = 32;

    private Json() {}

    public static String write(Object value) throws SigningflowException.InvalidRequestException {
        StringBuilder out = new StringBuilder();
        writeValue(value, out, 0);
        return out.toString();
    }

    public static Object read(String text) throws SigningflowException.ApiException {
        if (text == null) {
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }
        Parser parser = new Parser(text);
        Object value = parser.parse(0);
        parser.skipWs();
        if (!parser.done()) {
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        return null;
    }

    public static String asString(Object value) {
        return value instanceof String text ? text : "";
    }

    public static Integer asInt(Object value) {
        if (value instanceof Boolean) {
            return null;
        }
        if (value instanceof Long number) {
            if (number < Integer.MIN_VALUE || number > Integer.MAX_VALUE) {
                return null;
            }
            return number.intValue();
        }
        if (value instanceof Double number) {
            return number.intValue();
        }
        if (value instanceof String text) {
            try {
                return Integer.valueOf(text);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static void writeValue(Object value, StringBuilder out, int depth) throws SigningflowException.InvalidRequestException {
        if (depth > MAX_DEPTH) {
            throw new SigningflowException.InvalidRequestException("invalid request body");
        }
        if (value == null) {
            out.append("null");
            return;
        }
        if (value instanceof String text) {
            writeString(text, out);
            return;
        }
        if (value instanceof Boolean bool) {
            out.append(bool ? "true" : "false");
            return;
        }
        if (value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long) {
            out.append(value);
            return;
        }
        if (value instanceof Float || value instanceof Double) {
            double number = ((Number) value).doubleValue();
            if (Double.isNaN(number) || Double.isInfinite(number)) {
                throw new SigningflowException.InvalidRequestException("invalid request body");
            }
            out.append(value);
            return;
        }
        if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key)) {
                    throw new SigningflowException.InvalidRequestException("invalid request body");
                }
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(key, out);
                out.append(':');
                writeValue(entry.getValue(), out, depth + 1);
            }
            out.append('}');
            return;
        }
        if (value instanceof Iterable<?> items) {
            out.append('[');
            boolean first = true;
            for (Object item : items) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeValue(item, out, depth + 1);
            }
            out.append(']');
            return;
        }
        throw new SigningflowException.InvalidRequestException("invalid request body");
    }

    private static void writeString(String text, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static final class Parser {
        private final String text;
        private int index;

        private Parser(String text) {
            this.text = text;
        }

        private Object parse(int depth) throws SigningflowException.ApiException {
            if (depth > MAX_DEPTH) {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            skipWs();
            if (done()) {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            char c = text.charAt(index);
            if (c == '{') {
                return parseObject(depth);
            }
            if (c == '[') {
                return parseArray(depth);
            }
            if (c == '"') {
                return parseString();
            }
            if (c == 't' || c == 'f') {
                return parseBoolean();
            }
            if (c == 'n') {
                return parseNull();
            }
            if (c == '-' || (c >= '0' && c <= '9')) {
                return parseNumber();
            }
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }

        private Map<String, Object> parseObject(int depth) throws SigningflowException.ApiException {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWs();
            if (peek('}')) {
                index++;
                return map;
            }
            while (true) {
                skipWs();
                if (done() || text.charAt(index) != '"') {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                String key = parseString();
                skipWs();
                expect(':');
                map.put(key, parse(depth + 1));
                skipWs();
                if (peek('}')) {
                    index++;
                    return map;
                }
                expect(',');
            }
        }

        private List<Object> parseArray(int depth) throws SigningflowException.ApiException {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWs();
            if (peek(']')) {
                index++;
                return list;
            }
            while (true) {
                list.add(parse(depth + 1));
                skipWs();
                if (peek(']')) {
                    index++;
                    return list;
                }
                expect(',');
            }
        }

        private String parseString() throws SigningflowException.ApiException {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (!done()) {
                char c = text.charAt(index++);
                if (c == '"') {
                    return out.toString();
                }
                if (c == '\\') {
                    if (done()) {
                        break;
                    }
                    char escaped = text.charAt(index++);
                    switch (escaped) {
                        case '"', '\\', '/' -> out.append(escaped);
                        case 'b' -> out.append('\b');
                        case 'f' -> out.append('\f');
                        case 'n' -> out.append('\n');
                        case 'r' -> out.append('\r');
                        case 't' -> out.append('\t');
                        case 'u' -> out.append(parseHex());
                        default -> throw new SigningflowException.ApiException("The API returned invalid JSON.");
                    }
                    continue;
                }
                if (c < 0x20) {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                out.append(c);
            }
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }

        private char parseHex() throws SigningflowException.ApiException {
            if (index + 4 > text.length()) {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            int code = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(text.charAt(index++), 16);
                if (digit < 0) {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                code = (code << 4) + digit;
            }
            return (char) code;
        }

        private Boolean parseBoolean() throws SigningflowException.ApiException {
            if (text.startsWith("true", index)) {
                index += 4;
                return Boolean.TRUE;
            }
            if (text.startsWith("false", index)) {
                index += 5;
                return Boolean.FALSE;
            }
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }

        private Object parseNull() throws SigningflowException.ApiException {
            if (text.startsWith("null", index)) {
                index += 4;
                return null;
            }
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }

        private Number parseNumber() throws SigningflowException.ApiException {
            int start = index;
            if (peek('-')) {
                index++;
            }
            if (done() || !digit()) {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            if (text.charAt(index) == '0') {
                index++;
            } else {
                while (!done() && digit()) {
                    index++;
                }
            }
            boolean fractional = false;
            if (!done() && text.charAt(index) == '.') {
                fractional = true;
                index++;
                if (done() || !digit()) {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                while (!done() && digit()) {
                    index++;
                }
            }
            if (!done() && (text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
                fractional = true;
                index++;
                if (!done() && (text.charAt(index) == '+' || text.charAt(index) == '-')) {
                    index++;
                }
                if (done() || !digit()) {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                while (!done() && digit()) {
                    index++;
                }
            }
            String token = text.substring(start, index);
            try {
                if (!fractional) {
                    return Long.valueOf(token);
                }
                return Double.valueOf(token);
            } catch (NumberFormatException ex) {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
        }

        private boolean digit() {
            char c = text.charAt(index);
            return c >= '0' && c <= '9';
        }

        private void expect(char c) throws SigningflowException.ApiException {
            if (done() || text.charAt(index) != c) {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            index++;
        }

        private boolean peek(char c) {
            return !done() && text.charAt(index) == c;
        }

        private void skipWs() {
            while (!done()) {
                char c = text.charAt(index);
                if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
                    return;
                }
                index++;
            }
        }

        private boolean done() {
            return index >= text.length();
        }
    }
}
