package com.signingflow;

public final class StoredFile {
    private final String name;
    private final String id;

    StoredFile(String name, String id) {
        this.name = name;
        this.id = id;
    }

    public String name() { return name; }
    public String id() { return id; }
}
