# Changelog

## 0.1.0

First Java SDK for sending a document, reading envelope status, downloading a completed file, and verifying webhook signatures.

Install from a checkout with `mvn -B install` until the package is on Maven Central. The coordinates are `com.signingflow:signingflow`.

The API host is HTTPS `api.signingflow.com` unless a custom base URL is allowed. A file path is read only from `uploadRoot`, and only when the JVM can open it with `NOFOLLOW_LINKS` and report `unix:nlink`. A hard link and an absolute path are rejected. Byte uploads do not need that view. `constructEvent` returns `payload` and `bodySha256` of the raw body. A 409 is an idempotency error only when the body says the key was already used. A timed-out send is returned only when `sentTime` falls in the two minutes after the call started. The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading an API response at 8 MB. A query value that contains the API key is rejected, including when that key is percent-encoded. An API error does not keep an API key that contains a slash or a space, including when that key is percent-encoded in lowercase. A response that ends before its declared length is not treated as the resource. The client does not send the API key through a proxy.
