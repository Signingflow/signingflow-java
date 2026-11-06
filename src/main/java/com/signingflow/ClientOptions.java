package com.signingflow;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class ClientOptions {
    public static final String DEFAULT_BASE_URL = "https://api.signingflow.com";

    private final String workspaceId;
    private final String wireEnv;
    private final String baseUrl;
    private final boolean allowCustomBaseUrl;
    private final Duration timeout;
    private final int maxNetworkRetries;
    private final List<String> uploadHosts;
    private final String channel;
    private final String funnel;
    private final String uploadRoot;
    private final String caBundle;

    private ClientOptions(Builder builder) throws SigningflowException.InvalidRequestException {
        this.workspaceId = builder.workspaceId == null ? "" : builder.workspaceId.trim();
        if (this.workspaceId.isEmpty()) {
            throw new SigningflowException.InvalidRequestException("workspace_id is required.");
        }
        this.wireEnv = wire(builder.env);
        String base = builder.baseUrl == null || builder.baseUrl.isBlank() ? DEFAULT_BASE_URL : builder.baseUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        URI uri = Urls.parse(base);
        if (!"https".equals(uri.getScheme())) {
            throw new SigningflowException.InvalidRequestException("base_url must be https.");
        }
        if (uri.getRawUserInfo() != null) {
            throw new SigningflowException.InvalidRequestException("base_url must not include a username or password.");
        }
        String host = Urls.hostOf(uri);
        if (!Urls.OFFICIAL_HOST.equals(host) && !builder.allowCustomBaseUrl) {
            throw new SigningflowException.InvalidRequestException("base_url host must be api.signingflow.com, or set allow_custom_base_url.");
        }
        this.baseUrl = base;
        this.allowCustomBaseUrl = builder.allowCustomBaseUrl;
        if (builder.timeout == null || builder.timeout.isZero() || builder.timeout.isNegative()) {
            throw new SigningflowException.InvalidRequestException("timeout must be positive.");
        }
        this.timeout = builder.timeout;
        if (builder.maxNetworkRetries < 0) {
            throw new SigningflowException.InvalidRequestException("max_network_retries must be a whole number of zero or more.");
        }
        this.maxNetworkRetries = builder.maxNetworkRetries;
        this.uploadHosts = uploadHosts(builder.uploadHosts);
        this.channel = builder.channel == null ? "" : builder.channel.trim();
        this.funnel = builder.funnel == null ? "" : builder.funnel.trim();
        if (badHeader(this.workspaceId) || badHeader(this.channel) || badHeader(this.funnel)) {
            throw new SigningflowException.InvalidRequestException("invalid header value");
        }
        this.uploadRoot = builder.uploadRoot == null ? "" : builder.uploadRoot.trim();
        this.caBundle = builder.caBundle == null ? "" : builder.caBundle.trim();
    }

    public String workspaceId() { return workspaceId; }
    public String wireEnv() { return wireEnv; }
    public String baseUrl() { return baseUrl; }
    public boolean allowCustomBaseUrl() { return allowCustomBaseUrl; }
    public Duration timeout() { return timeout; }
    public int maxNetworkRetries() { return maxNetworkRetries; }
    public List<String> uploadHosts() { return uploadHosts; }
    public String channel() { return channel; }
    public String funnel() { return funnel; }
    public String uploadRoot() { return uploadRoot; }
    public String caBundle() { return caBundle; }

    public static Builder builder() {
        return new Builder();
    }

    static boolean badHeader(String value) {
        return value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\0') >= 0;
    }

    private static String wire(String env) throws SigningflowException.InvalidRequestException {
        if ("sandbox".equals(env) || "SANDBOX".equals(env)) {
            return "SANDBOX";
        }
        if ("live".equals(env) || "LIVE".equals(env)) {
            return "LIVE";
        }
        throw new SigningflowException.InvalidRequestException("env must be sandbox or live.");
    }

    private static List<String> uploadHosts(List<String> hosts) throws SigningflowException.InvalidRequestException {
        List<String> source = hosts == null ? List.of("storage.googleapis.com") : hosts;
        List<String> cleaned = new ArrayList<>();
        for (String host : source) {
            String value = host == null ? "" : host.trim().toLowerCase(Locale.ROOT);
            if (value.isEmpty()) {
                continue;
            }
            int dots = value.length() - value.replace(".", "").length();
            if (dots < 2 || value.startsWith(".") || value.endsWith(".") || value.contains("..")) {
                throw new SigningflowException.InvalidRequestException("Each upload_hosts entry must be a specific host, not a public suffix.");
            }
            cleaned.add(value);
        }
        return List.copyOf(cleaned);
    }

    public static final class Builder {
        private String workspaceId;
        private String env;
        private String baseUrl;
        private boolean allowCustomBaseUrl;
        private Duration timeout = Duration.ofSeconds(30);
        private int maxNetworkRetries = 2;
        private List<String> uploadHosts;
        private String channel = "";
        private String funnel = "";
        private String uploadRoot = "";
        private String caBundle = "";

        public Builder workspaceId(String value) { this.workspaceId = value; return this; }
        public Builder env(String value) { this.env = value; return this; }
        public Builder baseUrl(String value) { this.baseUrl = value; return this; }
        public Builder allowCustomBaseUrl(boolean value) { this.allowCustomBaseUrl = value; return this; }
        public Builder timeout(Duration value) { this.timeout = value; return this; }
        public Builder maxNetworkRetries(int value) { this.maxNetworkRetries = value; return this; }
        public Builder uploadHosts(List<String> value) { this.uploadHosts = value; return this; }
        public Builder channel(String value) { this.channel = value; return this; }
        public Builder funnel(String value) { this.funnel = value; return this; }
        public Builder uploadRoot(String value) { this.uploadRoot = value; return this; }
        public Builder caBundle(String value) { this.caBundle = value; return this; }

        public ClientOptions build() throws SigningflowException.InvalidRequestException {
            return new ClientOptions(this);
        }
    }
}
