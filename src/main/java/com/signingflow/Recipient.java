package com.signingflow;

public final class Recipient {
    private final String name;
    private final String email;

    public Recipient(String name, String email) {
        this.name = name;
        this.email = email;
    }

    public String name() { return name; }
    public String email() { return email; }
}
