package com.signingflow;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
public final class Page<T> {
    static final int MAX_PAGES = 100;

    private final List<T> data;
    private final String nextPageToken;
    private final Loader<T> load;

    Page(List<T> data, String nextPageToken, Loader<T> load) {
        this.data = List.copyOf(data);
        this.nextPageToken = nextPageToken == null ? "" : nextPageToken;
        this.load = load;
    }

    public List<T> data() { return data; }
    public String nextPageToken() { return nextPageToken; }

    public Iterable<T> all() {
        return () -> new Iterator<>() {
            private Page<T> page = Page.this;
            private int index;
            private final Set<String> seen = new HashSet<>();
            private int pages;
            private boolean finished;

            @Override
            public boolean hasNext() {
                advance();
                return !finished;
            }

            @Override
            public T next() {
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                return page.data.get(index++);
            }

            private void advance() {
                while (!finished && index >= page.data.size()) {
                    String token = page.nextPageToken;
                    if (token.isEmpty() || page.load == null) {
                        finished = true;
                        return;
                    }
                    if (!seen.add(token)) {
                        finished = true;
                        return;
                    }
                    pages++;
                    if (pages > MAX_PAGES) {
                        throw new TooManyPagesException();
                    }
                    try {
                        Page<T> next = page.load.load(token);
                        page = new Page<>(next.data, next.nextPageToken, page.load);
                    } catch (SigningflowException ex) {
                        throw new LoadException(ex);
                    }
                    index = 0;
                }
            }
        };
    }

    static String nextToken(Object body) {
        MapToken record = new MapToken(Json.asMap(body));
        String token = record.get("next_page_token");
        if (!token.isEmpty()) {
            return token;
        }
        return record.get("nextPageToken");
    }

    static List<Object> items(Object body, String key) {
        MapToken record = new MapToken(Json.asMap(body));
        Object raw = record.raw(key);
        if (raw instanceof List<?> list) {
            return new ArrayList<>(list);
        }
        return List.of();
    }

    static int pageSize(Integer value) throws SigningflowException.InvalidRequestException {
        if (value == null) {
            return 10;
        }
        if (value < 1 || value > 1000) {
            throw new SigningflowException.InvalidRequestException("page_size must be from 1 to 1000.");
        }
        return value;
    }

    interface Loader<T> {
        Page<T> load(String token) throws SigningflowException;
    }

    public static final class TooManyPagesException extends RuntimeException {
        public TooManyPagesException() {
            super("Too many pages.");
        }
    }

    public static final class LoadException extends RuntimeException {
        public LoadException(SigningflowException cause) {
            super(cause);
        }
    }

    private record MapToken(java.util.Map<String, Object> map) {
        private String get(String key) {
            return map == null ? "" : Json.asString(map.get(key));
        }

        private Object raw(String key) {
            return map == null ? null : map.get(key);
        }
    }
}
