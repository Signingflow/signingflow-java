package com.signingflow;

public final class SigningflowClient {
    private final ClientOptions options;
    private final Files files;
    private final Templates templates;
    private final Envelopes envelopes;
    private final WebhookUrls webhookUrls;
    private final WebhookDeliveries webhookDeliveries;

    public SigningflowClient(String apiKey, ClientOptions options) throws SigningflowException.InvalidRequestException {
        if (options == null) {
            throw new SigningflowException.InvalidRequestException("workspace_id is required.");
        }
        this.options = options;
        Transport transport = new Transport(apiKey, options);
        this.files = new Files(transport);
        this.templates = new Templates(transport);
        this.envelopes = new Envelopes(transport, files, templates);
        this.webhookUrls = new WebhookUrls(transport);
        this.webhookDeliveries = new WebhookDeliveries(transport);
    }

    public ClientOptions options() { return options; }
    public Files files() { return files; }
    public Templates templates() { return templates; }
    public Envelopes envelopes() { return envelopes; }
    public WebhookUrls webhookUrls() { return webhookUrls; }
    public WebhookDeliveries webhookDeliveries() { return webhookDeliveries; }
}
