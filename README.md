# signingflow

Java SDK for the Signingflow calls used to send a document, read envelope status, and receive webhooks.

The package talks to `https://api.signingflow.com`. Keep the API key on your server. Java 21 or newer is required. The SDK has no runtime dependencies.

```xml
<dependency>
  <groupId>com.signingflow</groupId>
  <artifactId>signingflow</artifactId>
  <version>0.1.0</version>
</dependency>
```

The coordinates are `com.signingflow:signingflow`. The package is not on Maven Central. Install it from a checkout of [github.com/Signingflow/signingflow-java](https://github.com/Signingflow/signingflow-java):

```bash
mvn -B install
```

```java
SigningflowClient signingflow = new SigningflowClient(
    System.getenv("SIGNINGFLOW_API_KEY"),
    ClientOptions.builder()
        .workspaceId(System.getenv("SIGNINGFLOW_WORKSPACE_ID"))
        .env("sandbox")
        .build());

Envelope envelope = signingflow.envelopes().sendDocument(
    "NDA",
    pdfBytes,
    null,
    "contract.pdf",
    java.util.List.of(new Recipient("Ada Lovelace", "ada@example.com")),
    "Please sign");
```

`file` is a `byte[]`. `null` means no bytes. A zero-length array is an empty file. A disk path is `path`, and it is read only from `uploadRoot`. That directory must be one this process writes. The open refuses a symlink, a hard link, an absolute path, and a path that leaves the directory. Path reads use `LinkOption.NOFOLLOW_LINKS` and the `unix:nlink` attribute. On a JVM without that view, a path is refused and the file is not opened. Passing bytes in `file` does not need it. Do not pass a path from a request field.

`env` is `sandbox` or `live`. The client always sends `X-Request-Env`. A missing environment header is treated as live by the API, so the client rejects a missing environment.

`baseUrl` must be `https`. The host is `api.signingflow.com` unless `allowCustomBaseUrl` is set. A username or password on the URL is rejected. The host comparison is case-sensitive. There is no process-wide API key. The client does not use `HTTPS_PROXY`.

The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading once an API response passes 8 MB. A response that ends before its declared length is not treated as the resource.

## Send and read

`envelopes().prepareDraft` stores one PDF and creates a draft. It does not email anyone.

`envelopes().sendDocument` stores the PDF, creates the draft, adds the recipients to the first document, and sends. `envelopes().sendFromTemplate` starts from `templates/{id}`.

If update or send fails, the error includes `envelopeName` for the draft that was saved. After a timeout, the client returns the envelope only when `sentTime` is within two minutes after the call started and not more than a minute ahead of this clock. An older or far-future timestamp is an error.

`envelopes().list("needAction", null, null, null)` reads pages of 10. `pageSize` can be from 1 to 1000. Omitting it selects 10. `0` is rejected. `all()` walks later pages and stops after 100 follow-up pages or a repeated token.

`envelopes().downloadCompleted(name)` reads the envelope first. It requests the download URL only when the state is `COMPLETED`. The download call returns `uri`, `downloadTime`, and `etag`. This client does not GET `uri`. Treat that URL as untrusted until your application checks the host. Do not send the API key to it.

`envelopes().remind(name)` notifies people who can still sign. The call is not idempotent.

## Idempotency

Creates and sends send a UUID `idempotencyKey` in the JSON body. The same key is stored for the whole environment. A repeat returns HTTP 409 and does not return the original resource. The SDK raises `SigningflowException.IdempotencyException` with `resourceName` when the error includes one. It does not treat that response as success.

Pass the same idempotency key only to retry one request after a timeout. `update` and `remind` are not retried automatically. A query value that contains the API key is rejected, including when that key is percent-encoded.

## Webhooks

```java
WebhookUrl destination = signingflow.webhookUrls().create(
    "Envelope events",
    "https://example.com/webhooks/signingflow",
    java.util.List.of("DOC_ENVELOPE_COMPLETED"),
    null,
    "");
String secret = WebhookUrls.signingSecretOf(destination);
```

Store that secret from the create response. A later `retrieve` does not include it. Do not set `httpConfig`. `auth` `NONE` is rejected.

```java
Event event = Webhooks.constructEvent(rawBody, signatureHeader, secret, previousSecret, previousSignature);
event.payload();
event.bodySha256();
```

`rawBody` is the exact request bytes. Store `bodySha256` with the event so a repeat delivery is recognizable. `previousSecret` is checked only together with `previousSignature`.

## Errors

| Exception | When |
| --- | --- |
| `AuthenticationException` | HTTP 401 |
| `PermissionException` | HTTP 403 |
| `IdempotencyException` | HTTP 409 whose body mentions idempotency |
| `RateLimitException` | HTTP 429 |
| `InvalidRequestException` | Other HTTP 4xx, and rejected arguments |
| `ApiException` | HTTP 5xx, or a body that is not JSON |
| `ConnectionException` | The API could not be reached, or the call timed out |
| `SignatureVerificationException` | A webhook signature did not match |

An API error does not keep an API key that contains a slash or a space. `fieldViolations` lists field errors returned by the API.
