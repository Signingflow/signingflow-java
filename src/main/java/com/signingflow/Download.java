package com.signingflow;

public final class Download {
    private final String uri;
    private final String downloadTime;
    private final String etag;

    Download(String uri, String downloadTime, String etag) {
        this.uri = uri;
        this.downloadTime = downloadTime;
        this.etag = etag;
    }

    public String uri() { return uri; }
    public String downloadTime() { return downloadTime; }
    public String etag() { return etag; }
}
