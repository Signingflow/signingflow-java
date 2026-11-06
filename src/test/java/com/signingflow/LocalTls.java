package com.signingflow;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

final class LocalTls implements AutoCloseable {
    final int port;
    final Path certificate;
    final List<Hit> hits = java.util.Collections.synchronizedList(new ArrayList<>());
    final ConcurrentLinkedQueue<Reply> replies = new ConcurrentLinkedQueue<>();
    volatile boolean pageForever;
    private final AtomicInteger pages = new AtomicInteger();
    private final SSLServerSocket listen;
    private final Thread thread;
    private volatile boolean stop;

    private LocalTls(SSLServerSocket listen, Path certificate) {
        this.listen = listen;
        this.port = listen.getLocalPort();
        this.certificate = certificate;
        this.thread = new Thread(this::serve, "signingflow-test-tls");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    static LocalTls start() throws Exception {
        Path dir = Files.createTempDirectory("signingflow-java");
        Path store = dir.resolve("probe.p12");
        Path pem = dir.resolve("probe.pem");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        int generated = new ProcessBuilder(
                keytool, "-genkeypair", "-alias", "probe", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-keystore", store.toString(), "-storetype", "PKCS12",
                "-storepass", "changeit", "-keypass", "changeit", "-dname", "CN=127.0.0.1",
                "-ext", "SAN=IP:127.0.0.1")
                .redirectErrorStream(true)
                .start()
                .waitFor();
        if (generated != 0) {
            throw new IllegalStateException("keytool genkeypair failed");
        }
        int exported = new ProcessBuilder(
                keytool, "-exportcert", "-alias", "probe", "-keystore", store.toString(),
                "-storepass", "changeit", "-rfc", "-file", pem.toString())
                .redirectErrorStream(true)
                .start()
                .waitFor();
        if (exported != 0) {
            throw new IllegalStateException("keytool exportcert failed");
        }
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keys.load(in, "changeit".toCharArray());
        }
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, "changeit".toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(factory.getKeyManagers(), null, null);
        SSLServerSocket socket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
        return new LocalTls(socket, pem);
    }

    void reset() {
        hits.clear();
        replies.clear();
        pageForever = false;
        pages.set(0);
    }

    void json(int status, String body) {
        replies.add(new Reply(status, body.getBytes(StandardCharsets.UTF_8), "application/json", "normal", Map.of()));
    }

    void json(String body) {
        json(200, body);
    }

    void mode(String mode, int status, String body) {
        replies.add(new Reply(status, body.getBytes(StandardCharsets.UTF_8), "application/json", mode, Map.of()));
    }

    void bytes(int status, byte[] body, String type, Map<String, String> headers) {
        replies.add(new Reply(status, body, type, "normal", headers));
    }

    @Override
    public void close() {
        stop = true;
        try {
            listen.close();
        } catch (IOException ignored) {
            // The accept loop exits when the socket closes.
        }
        try {
            thread.join(2000);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private void serve() {
        while (!stop) {
            try {
                Socket socket = listen.accept();
                Thread worker = new Thread(() -> {
                    try (socket) {
                        socket.setSoTimeout(4000);
                        handle(socket);
                    } catch (Exception ignored) {
                        // A timed-out client closes the socket while a stall is still open.
                    }
                }, "signingflow-test-tls-conn");
                worker.setDaemon(true);
                worker.start();
            } catch (Exception ignored) {
                if (stop) {
                    return;
                }
            }
        }
    }

    private void handle(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] headerBytes;
        try {
            headerBytes = readHeaders(in);
        } catch (EOFException ex) {
            return;
        }
        String header = new String(headerBytes, StandardCharsets.ISO_8859_1);
        String[] lines = header.split("\r\n");
        String[] request = lines[0].split(" ");
        if (request.length < 2) {
            return;
        }
        String target = request[1];
        int queryAt = target.indexOf('?');
        String path = queryAt < 0 ? target : target.substring(0, queryAt);
        String query = queryAt < 0 ? "" : target.substring(queryAt + 1);
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.put(lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT), lines[i].substring(colon + 1).trim());
            }
        }
        int length = 0;
        if (headers.getOrDefault("content-length", "").matches("\\d+")) {
            length = Integer.parseInt(headers.get("content-length"));
        }
        byte[] body = in.readNBytes(length);
        hits.add(new Hit(request[0], path, query, headers, body));
        Reply reply = pageForever ? page(query) : replies.poll();
        if (reply == null) {
            reply = new Reply(200, "{}".getBytes(StandardCharsets.UTF_8), "application/json", "normal", Map.of());
        }
        if ("drop".equals(reply.mode)) {
            return;
        }
        if ("stall".equals(reply.mode)) {
            try {
                Thread.sleep(3000);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        OutputStream out = socket.getOutputStream();
        if ("redirect".equals(reply.mode)) {
            out.write(("HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:" + port + "/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            return;
        }
        StringBuilder head = new StringBuilder();
        head.append("HTTP/1.1 ").append(reply.status).append(" X\r\n");
        if ("huge".equals(reply.mode)) {
            head.append("Content-Type: application/json\r\nContent-Length: 20000000\r\nConnection: close\r\n\r\n");
            out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
            out.write(reply.body);
            return;
        }
        if ("short".equals(reply.mode)) {
            head.append("Content-Type: application/json\r\nContent-Length: 80\r\nConnection: close\r\n\r\n");
            out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
            out.write(reply.body);
            return;
        }
        head.append("Content-Type: ").append(reply.type).append("\r\n");
        reply.headers.forEach((name, value) -> head.append(name).append(": ").append(value).append("\r\n"));
        head.append("Content-Length: ").append(reply.body.length).append("\r\nConnection: close\r\n\r\n");
        out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(reply.body);
    }

    private Reply page(String query) {
        int n = pages.incrementAndGet();
        String body = "{\"envelopes\":[{\"name\":\"envelopes/11111111-1111-4111-8111-111111111111\"}],\"nextPageToken\":\"page-" + n + "\"}";
        return new Reply(200, body.getBytes(StandardCharsets.UTF_8), "application/json", "normal", Map.of());
    }

    private static byte[] readHeaders(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int a = 0;
        int b = 0;
        int c = 0;
        while (true) {
            int d = in.read();
            if (d < 0) {
                throw new EOFException();
            }
            out.write(d);
            if (a == '\r' && b == '\n' && c == '\r' && d == '\n') {
                return out.toByteArray();
            }
            a = b;
            b = c;
            c = d;
            if (out.size() > 65536) {
                throw new IOException("headers too large");
            }
        }
    }

    record Reply(int status, byte[] body, String type, String mode, Map<String, String> headers) {}

    record Hit(String method, String path, String query, Map<String, String> headers, byte[] body) {
        String header(String name) {
            return headers.getOrDefault(name.toLowerCase(Locale.ROOT), "");
        }

        String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }
}
