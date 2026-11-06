package com.signingflow;

import java.util.List;

public final class WebhookUrl {
    private final String name;
    private final String displayName;
    private final String httpRequestUri;
    private final List<String> events;
    private final String signingSecret;

    WebhookUrl(String name, String displayName, String httpRequestUri, List<String> events, String signingSecret) {
        this.name = name;
        this.displayName = displayName;
        this.httpRequestUri = httpRequestUri;
        this.events = events;
        this.signingSecret = signingSecret;
    }

    public String name() { return name; }
    public String displayName() { return displayName; }
    public String httpRequestUri() { return httpRequestUri; }
    public List<String> events() { return events; }
    public String signingSecret() { return signingSecret; }
}
