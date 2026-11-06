package com.signingflow;

public final class Event {
    private final Object payload;
    private final String bodySha256;

    Event(Object payload, String bodySha256) {
        this.payload = payload;
        this.bodySha256 = bodySha256;
    }

    public Object payload() { return payload; }
    public String bodySha256() { return bodySha256; }
}
