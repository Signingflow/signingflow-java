package com.signingflow;

public final class WebhookDelivery {
    private final String name;
    private final String event;

    WebhookDelivery(String name, String event) {
        this.name = name;
        this.event = event;
    }

    public String name() { return name; }
    public String event() { return event; }
}
