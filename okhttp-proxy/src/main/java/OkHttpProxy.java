import com.google.gson.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import okhttp3.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.*;
import java.util.concurrent.*;
import java.io.ByteArrayOutputStream;
import javax.net.ssl.*;

/**
 * Local HTTP proxy that routes requests through real OkHttp 4.11.0.
 * Python sends request specs as JSON, this server executes them with
 * authentic OkHttp TLS + HTTP/2 fingerprint, returns the response.
 *
 * Also supports WebSocket relay: Python can open/send/receive/close
 * WebSocket connections through OkHttp (same Conscrypt TLS fingerprint).
 *
 * Conscrypt (BoringSSL) is registered as the default TLS provider so the
 * JA3/JA4 fingerprint matches a real Android device (Android uses BoringSSL
 * via Conscrypt, not Java's default SunJSSE).
 *
 * Usage: java -jar okhttp-proxy.jar [port]
 *   port=0 means auto-assign; the chosen port is printed to stdout.
 */
public class OkHttpProxy {

    private static final ConnectionPool POOL =
            new ConnectionPool(64, 5, TimeUnit.MINUTES);

    private static final OkHttpClient BASE;

    /* ---- WebSocket session storage ---- */
    private static final ConcurrentHashMap<String, WsSession> WS_SESSIONS =
            new ConcurrentHashMap<>();

    private static class WsSession {
        volatile WebSocket ws;
        final LinkedBlockingQueue<String> inbox = new LinkedBlockingQueue<>();
        volatile boolean closed = false;
        volatile int closeCode = -1;
        volatile String closeReason = "";
    }

    static {
        // Register Conscrypt (BoringSSL) as the top-priority TLS provider.
        // This makes OkHttp's TLS fingerprint match a real Android device
        // instead of desktop Java's SunJSSE (completely different JA3/JA4).
        boolean conscryptLoaded = false;
        try {
            Class<?> conscrypt = Class.forName("org.conscrypt.OpenSSLProvider");
            Security.insertProviderAt(
                    (java.security.Provider) conscrypt.getConstructor().newInstance(), 1);
            conscryptLoaded = true;
        } catch (Exception e) {
            System.err.println("[okhttp] WARNING: Conscrypt not found: " + e.getMessage());
        }
        // Print TLS status to stdout BEFORE PORT line — Python reads this
        System.out.println("TLS:" + (conscryptLoaded ? "conscrypt" : "default"));
        System.out.flush();

        Dispatcher d = new Dispatcher();
        d.setMaxRequests(256);
        d.setMaxRequestsPerHost(32);

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectionPool(POOL)
                .dispatcher(d)
                .followRedirects(false)
                .followSslRedirects(false)
                // NetworkInterceptor: move Cookie header AFTER OkHttp-added headers
                // (Content-Length, Host, Connection, Accept-Encoding).
                // Real OkHttp CookieJar adds Cookie via BridgeInterceptor AFTER
                // Accept-Encoding. Without this, our Cookie (passed as custom header)
                // appears BEFORE those headers — detectable header order anomaly.
                .addNetworkInterceptor(chain -> {
                    Request request = chain.request();
                    String cookie = request.header("Cookie");
                    if (cookie != null) {
                        Request fixed = request.newBuilder()
                                .removeHeader("Cookie")
                                .addHeader("Cookie", cookie)
                                .build();
                        return chain.proceed(fixed);
                    }
                    return chain.proceed(request);
                });

        // If Conscrypt loaded, configure explicit BoringSSL SSLContext + TrustManager
        // so OkHttp uses Conscrypt directly (not through Jdk9Platform detection).
        // Also configure Android-like connection spec with matching cipher suites.
        if (conscryptLoaded) {
            try {
                SSLContext ctx = SSLContext.getInstance("TLSv1.3", "Conscrypt");
                ctx.init(null, null, null);

                // Get Conscrypt's default TrustManager
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                tmf.init((java.security.KeyStore) null);
                X509TrustManager tm = null;
                for (TrustManager t : tmf.getTrustManagers()) {
                    if (t instanceof X509TrustManager) { tm = (X509TrustManager) t; break; }
                }

                // Custom SSLSocketFactory that enables session tickets (Android behavior)
                final SSLSocketFactory baseSsf = ctx.getSocketFactory();
                SSLSocketFactory androidSsf = new SSLSocketFactory() {
                    @Override public String[] getDefaultCipherSuites() {
                        return baseSsf.getDefaultCipherSuites();
                    }
                    @Override public String[] getSupportedCipherSuites() {
                        return baseSsf.getSupportedCipherSuites();
                    }
                    @Override public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose) throws IOException {
                        SSLSocket ssl = (SSLSocket) baseSsf.createSocket(s, host, port, autoClose);
                        configureAndroid(ssl);
                        return ssl;
                    }
                    @Override public java.net.Socket createSocket(String host, int port) throws IOException {
                        SSLSocket ssl = (SSLSocket) baseSsf.createSocket(host, port);
                        configureAndroid(ssl);
                        return ssl;
                    }
                    @Override public java.net.Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
                        SSLSocket ssl = (SSLSocket) baseSsf.createSocket(host, port, localHost, localPort);
                        configureAndroid(ssl);
                        return ssl;
                    }
                    @Override public java.net.Socket createSocket(InetAddress host, int port) throws IOException {
                        SSLSocket ssl = (SSLSocket) baseSsf.createSocket(host, port);
                        configureAndroid(ssl);
                        return ssl;
                    }
                    @Override public java.net.Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                        SSLSocket ssl = (SSLSocket) baseSsf.createSocket(address, port, localAddress, localPort);
                        configureAndroid(ssl);
                        return ssl;
                    }
                    private void configureAndroid(SSLSocket ssl) {
                        try {
                            // Enable session tickets — Android always does this
                            Class<?> c = Class.forName("org.conscrypt.Conscrypt");
                            java.lang.reflect.Method m = c.getMethod(
                                    "setUseSessionTickets", SSLSocket.class, boolean.class);
                            m.invoke(null, ssl, true);
                        } catch (Exception ignored) {}
                    }
                };

                if (tm != null) {
                    builder.sslSocketFactory(androidSsf, tm);
                }
            } catch (Exception e) {
                System.err.println("[okhttp] WARNING: Could not configure Conscrypt SSLContext: " + e);
            }
        }

        BASE = builder.build();
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 0;
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        srv.createContext("/req", OkHttpProxy::handleRequest);
        srv.createContext("/ws/open", OkHttpProxy::handleWsOpen);
        srv.createContext("/ws/send", OkHttpProxy::handleWsSend);
        srv.createContext("/ws/recv", OkHttpProxy::handleWsRecv);
        srv.createContext("/ws/close", OkHttpProxy::handleWsClose);
        srv.createContext("/ws2/open", OkHttpProxy::handleWs2Open);
        srv.createContext("/ws2/send", OkHttpProxy::handleWs2Send);
        srv.createContext("/ws2/recv", OkHttpProxy::handleWs2Recv);
        srv.createContext("/ws2/close", OkHttpProxy::handleWs2Close);
        srv.createContext("/health", ex -> reply(ex, 200, "{\"ok\":true}"));
        srv.setExecutor(Executors.newCachedThreadPool());
        srv.start();
        // Python reads this line to discover the port
        System.out.println("PORT:" + srv.getAddress().getPort());
        System.out.flush();
    }

    /* ---- helpers ---- */

    private static byte[] readAll(InputStream is) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        int n;
        while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
        return buf.toByteArray();
    }

    private static void reply(HttpExchange ex, int code, String body)
            throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    /* ---- Build per-request OkHttpClient with proxy ---- */

    private static OkHttpClient buildClient(JsonObject req, int timeout) {
        OkHttpClient.Builder cb = BASE.newBuilder()
                .connectTimeout(timeout, TimeUnit.SECONDS)
                .readTimeout(timeout, TimeUnit.SECONDS)
                .writeTimeout(timeout, TimeUnit.SECONDS);

        if (req.has("proxy") && req.get("proxy").isJsonObject()) {
            JsonObject p = req.getAsJsonObject("proxy");
            String host  = p.get("host").getAsString();
            int    pport = p.get("port").getAsInt();
            String type  = p.has("type") ? p.get("type").getAsString() : "http";

            Proxy.Type pt = type.startsWith("socks")
                    ? Proxy.Type.SOCKS : Proxy.Type.HTTP;
            cb.proxy(new Proxy(pt, new InetSocketAddress(host, pport)));

            if (p.has("user") && !p.get("user").isJsonNull()) {
                String u  = p.get("user").getAsString();
                String pw = p.has("pass") && !p.get("pass").isJsonNull()
                        ? p.get("pass").getAsString() : "";
                // Preemptive proxy auth — send Proxy-Authorization on FIRST request
                // (some proxies close connection on 407 instead of allowing retry)
                String proxyAuth = Credentials.basic(u, pw);
                cb.addNetworkInterceptor(chain -> {
                    Request r = chain.request();
                    if (r.header("Proxy-Authorization") == null) {
                        r = r.newBuilder()
                                .header("Proxy-Authorization", proxyAuth)
                                .build();
                    }
                    return chain.proceed(r);
                });
                cb.proxyAuthenticator((route, resp) -> {
                    if (resp.request().header("Proxy-Authorization") != null)
                        return null;
                    return resp.request().newBuilder()
                            .header("Proxy-Authorization", proxyAuth)
                            .build();
                });
            }
        }

        return cb.build();
    }

    /* ---- HTTP request handler ---- */

    private static void handleRequest(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            reply(exchange, 405, "{\"error\":\"POST only\"}");
            return;
        }

        String raw;
        try (InputStream is = exchange.getRequestBody()) {
            raw = new String(readAll(is), StandardCharsets.UTF_8);
        }

        try {
            JsonObject req = JsonParser.parseString(raw).getAsJsonObject();
            String method = req.get("method").getAsString().toUpperCase();
            String url    = req.get("url").getAsString();
            int timeout   = req.has("timeout") ? req.get("timeout").getAsInt() : 30;

            // --- Headers (preserve exact order from Python) ---
            okhttp3.Headers.Builder hb = new okhttp3.Headers.Builder();
            if (req.has("headers") && req.get("headers").isJsonArray()) {
                for (JsonElement el : req.getAsJsonArray("headers")) {
                    JsonArray pair = el.getAsJsonArray();
                    hb.add(pair.get(0).getAsString(), pair.get(1).getAsString());
                }
            }

            // --- Request body ---
            // Use null MediaType so OkHttp does NOT override the Content-Type
            // header that Python already set.  BridgeInterceptor only touches
            // Content-Type when body.contentType() != null.
            RequestBody body = null;
            if (req.has("body") && !req.get("body").isJsonNull()) {
                byte[] bytes = req.get("body").getAsString()
                                  .getBytes(StandardCharsets.UTF_8);
                body = RequestBody.create(bytes, (MediaType) null);
            }
            // GET / HEAD must not carry a body
            if ("GET".equals(method) || "HEAD".equals(method)) body = null;
            // POST / PATCH / PUT need a body — empty if none provided
            if (body == null && ("POST".equals(method) || "PATCH".equals(method)
                    || "PUT".equals(method))) {
                body = RequestBody.create(new byte[0], (MediaType) null);
            }

            Request okReq = new Request.Builder()
                    .url(url)
                    .headers(hb.build())
                    .method(method, body)
                    .build();

            OkHttpClient client = buildClient(req, timeout);

            // --- Execute & return ---
            try (Response resp = client.newCall(okReq).execute()) {
                // Log HTTP/2 connection info
                String protocol = resp.protocol().toString();
                if (System.getenv("DEBUG_PROXY") != null) {
                    System.err.println("[req] " + method + " " + url.substring(0, Math.min(url.length(), 60)) + " -> " + resp.code() + " " + protocol);
                }
                JsonObject out = new JsonObject();
                out.addProperty("status", resp.code());

                // Headers as [[name,value], ...] — supports duplicates
                JsonArray rh = new JsonArray();
                for (int i = 0; i < resp.headers().size(); i++) {
                    JsonArray pair = new JsonArray();
                    pair.add(resp.headers().name(i));
                    pair.add(resp.headers().value(i));
                    rh.add(pair);
                }
                out.add("headers", rh);

                ResponseBody rb = resp.body();
                out.addProperty("body", rb != null ? rb.string() : "");
                out.addProperty("url", resp.request().url().toString());

                reply(exchange, 200, out.toString());
            }
        } catch (Exception e) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            reply(exchange, 500, err.toString());
        }
    }

    /* ---- WebSocket relay handlers ---- */

    /**
     * POST /ws/open — Open a WebSocket via OkHttp with permessage-deflate DISABLED.
     * NetworkInterceptor strips Sec-WebSocket-Extensions so server doesn't negotiate compression.
     * Body: {"url":"wss://...", "headers":[[k,v],...], "proxy":{...}, "timeout":30}
     * Returns: {"id":"session-id"}
     */
    private static void handleWsOpen(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            reply(exchange, 405, "{\"error\":\"POST only\"}");
            return;
        }

        String raw;
        try (InputStream is = exchange.getRequestBody()) {
            raw = new String(readAll(is), StandardCharsets.UTF_8);
        }

        try {
            JsonObject req = JsonParser.parseString(raw).getAsJsonObject();
            String url = req.get("url").getAsString();
            int timeout = req.has("timeout") ? req.get("timeout").getAsInt() : 30;

            // Build headers
            okhttp3.Headers.Builder hb = new okhttp3.Headers.Builder();
            if (req.has("headers") && req.get("headers").isJsonArray()) {
                for (JsonElement el : req.getAsJsonArray("headers")) {
                    JsonArray pair = el.getAsJsonArray();
                    hb.add(pair.get(0).getAsString(), pair.get(1).getAsString());
                }
            }

            Request wsReq = new Request.Builder()
                    .url(url)
                    .headers(hb.build())
                    .build();

            // Build client — let OkHttp negotiate permessage-deflate naturally.
            // Do NOT strip Sec-WebSocket-Extensions, do NOT set minWebSocketMessageToCompress.
            // OkHttp will compress outgoing frames with deflate, Discord decompresses them.
            // Discord sends responses compressed with zstd-stream (URL param).
            OkHttpClient client = buildClient(req, timeout).newBuilder()
                    .readTimeout(0, TimeUnit.SECONDS)
                    .writeTimeout(30, TimeUnit.SECONDS)
                    .build();

            String sessionId = UUID.randomUUID().toString();
            CountDownLatch openLatch = new CountDownLatch(1);
            final String[] openError = {null};
            WsSession session = new WsSession();

            WebSocket ws = client.newWebSocket(wsReq, new WebSocketListener() {
                @Override
                public void onOpen(WebSocket webSocket, Response response) {
                    // Log response headers for debugging WS negotiation
                    if (System.getenv("DEBUG_PROXY") != null) {
                        System.err.println("[ws-open] status=" + response.code());
                        for (String name : response.headers().names()) {
                            System.err.println("[ws-open] " + name + ": " + response.header(name));
                        }
                    }
                    openLatch.countDown();
                }

                @Override
                public void onMessage(WebSocket webSocket, String text) {
                    session.inbox.offer(text);
                }

                @Override
                public void onMessage(WebSocket webSocket, okio.ByteString bytes) {
                    session.inbox.offer("__BIN__" + bytes.base64());
                }

                @Override
                public void onClosing(WebSocket webSocket, int code, String reason) {
                    if (System.getenv("DEBUG_PROXY") != null) {
                        System.err.println("[ws-closing] code=" + code + " reason=" + reason);
                    }
                    session.closed = true;
                    session.closeCode = code;
                    session.closeReason = reason;
                    session.inbox.offer("__WS_CLOSED__");
                    webSocket.close(code, reason);
                }

                @Override
                public void onClosed(WebSocket webSocket, int code, String reason) {
                    session.closed = true;
                    session.closeCode = code;
                    session.closeReason = reason;
                    session.inbox.offer("__WS_CLOSED__");
                }

                @Override
                public void onFailure(WebSocket webSocket, Throwable t, Response response) {
                    String errMsg = t.getClass().getSimpleName() + ": " + t.getMessage();
                    if (System.getenv("DEBUG_PROXY") != null) {
                        System.err.println("[ws-fail] " + errMsg);
                        if (response != null) {
                            System.err.println("[ws-fail] response=" + response.code());
                        }
                    }
                    openError[0] = errMsg;
                    session.closed = true;
                    session.inbox.offer("__WS_CLOSED__");
                    openLatch.countDown();
                }
            });

            session.ws = ws;

            boolean opened = openLatch.await(timeout, TimeUnit.SECONDS);

            if (!opened || openError[0] != null) {
                ws.cancel();
                String err = openError[0] != null ? openError[0] : "timeout";
                JsonObject errObj = new JsonObject();
                errObj.addProperty("error", err);
                reply(exchange, 500, errObj.toString());
                return;
            }

            WS_SESSIONS.put(sessionId, session);

            JsonObject out = new JsonObject();
            out.addProperty("id", sessionId);
            reply(exchange, 200, out.toString());
        } catch (Exception e) {
            java.io.StringWriter sw = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            System.err.println("[ws-open ERROR] " + sw);
            JsonObject err = new JsonObject();
            err.addProperty("error",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            reply(exchange, 500, err.toString());
        }
    }

    /**
     * POST /ws/send — Send a text message on an open WebSocket.
     * Body: {"id":"session-id", "text":"..."}
     * Returns: {"ok":true}
     */
    private static void handleWsSend(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            reply(exchange, 405, "{\"error\":\"POST only\"}");
            return;
        }

        String raw;
        try (InputStream is = exchange.getRequestBody()) {
            raw = new String(readAll(is), StandardCharsets.UTF_8);
        }

        try {
            JsonObject req = JsonParser.parseString(raw).getAsJsonObject();
            String id = req.get("id").getAsString();
            String text = req.get("text").getAsString();

            WsSession session = WS_SESSIONS.get(id);
            if (session == null) {
                reply(exchange, 404, "{\"error\":\"session not found\"}");
                return;
            }
            if (session.closed) {
                reply(exchange, 410, "{\"error\":\"websocket closed\"}");
                return;
            }

            if (System.getenv("DEBUG_PROXY") != null) {
                System.err.println("[ws-send] len=" + text.length() + " data=" + text.substring(0, Math.min(text.length(), 120)));
            }

            boolean binary = req.has("binary") && req.get("binary").getAsBoolean();
            if (binary) {
                byte[] bytes = java.util.Base64.getDecoder().decode(text);
                session.ws.send(okio.ByteString.of(bytes));
                if (System.getenv("DEBUG_PROXY") != null) {
                    System.err.println("[ws-send-bin] " + bytes.length + " bytes");
                }
            } else {
                session.ws.send(text);
            }
            reply(exchange, 200, "{\"ok\":true}");
        } catch (Exception e) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            reply(exchange, 500, err.toString());
        }
    }

    /**
     * POST /ws/recv — Receive the next message (blocks up to timeout).
     * Body: {"id":"session-id", "timeout":10}
     * Returns: {"text":"..."} or {"error":"timeout"} or {"closed":true,"code":1000}
     */
    private static void handleWsRecv(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            reply(exchange, 405, "{\"error\":\"POST only\"}");
            return;
        }

        String raw;
        try (InputStream is = exchange.getRequestBody()) {
            raw = new String(readAll(is), StandardCharsets.UTF_8);
        }

        try {
            JsonObject req = JsonParser.parseString(raw).getAsJsonObject();
            String id = req.get("id").getAsString();
            int timeout = req.has("timeout") ? req.get("timeout").getAsInt() : 10;

            WsSession session = WS_SESSIONS.get(id);
            if (session == null) {
                reply(exchange, 404, "{\"error\":\"session not found\"}");
                return;
            }

            String msg = session.inbox.poll(timeout, TimeUnit.SECONDS);
            if (msg == null) {
                reply(exchange, 200, "{\"error\":\"timeout\"}");
                return;
            }
            if ("__WS_CLOSED__".equals(msg)) {
                JsonObject out = new JsonObject();
                out.addProperty("closed", true);
                out.addProperty("code", session.closeCode);
                out.addProperty("reason", session.closeReason);
                reply(exchange, 200, out.toString());
                return;
            }

            JsonObject out = new JsonObject();
            out.addProperty("text", msg);
            reply(exchange, 200, out.toString());
        } catch (Exception e) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            reply(exchange, 500, err.toString());
        }
    }

    /**
     * POST /ws/close — Close a WebSocket connection.
     * Body: {"id":"session-id", "code":1000, "reason":""}
     * Returns: {"ok":true}
     */
    private static void handleWsClose(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            reply(exchange, 405, "{\"error\":\"POST only\"}");
            return;
        }

        String raw;
        try (InputStream is = exchange.getRequestBody()) {
            raw = new String(readAll(is), StandardCharsets.UTF_8);
        }

        try {
            JsonObject req = JsonParser.parseString(raw).getAsJsonObject();
            String id = req.get("id").getAsString();
            int code = req.has("code") ? req.get("code").getAsInt() : 1000;
            String reason = req.has("reason") ? req.get("reason").getAsString() : "";

            WsSession session = WS_SESSIONS.remove(id);
            if (session == null) {
                reply(exchange, 200, "{\"ok\":true}");
                return;
            }

            try {
                session.ws.close(code, reason);
            } catch (Exception ignored) {
                session.ws.cancel();
            }
            reply(exchange, 200, "{\"ok\":true}");
        } catch (Exception e) {
            JsonObject err = new JsonObject();
            err.addProperty("error",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            reply(exchange, 500, err.toString());
        }
    }

    /* ==== JDK java.net.http WebSocket (ws2) — no permessage-deflate, clean frames ==== */

    private static final ConcurrentHashMap<String, Ws2Session> WS2_SESSIONS = new ConcurrentHashMap<>();

    private static class Ws2Session {
        volatile java.net.http.WebSocket ws;
        final LinkedBlockingQueue<String> inbox = new LinkedBlockingQueue<>();
        volatile boolean closed = false;
        volatile int closeCode = -1;
        volatile String closeReason = "";
    }

    private static void handleWs2Open(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { reply(exchange, 405, "{\"error\":\"POST only\"}"); return; }
        String raw; try (InputStream is = exchange.getRequestBody()) { raw = new String(readAll(is), StandardCharsets.UTF_8); }
        try {
            JsonObject req = JsonParser.parseString(raw).getAsJsonObject();
            String url = req.get("url").getAsString();
            int timeout = req.has("timeout") ? req.get("timeout").getAsInt() : 30;

            // Build HttpClient with proxy if specified
            java.net.http.HttpClient.Builder hcb = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(timeout));

            // Configure SSL to trust all certs (like OkHttp does for proxies)
            try {
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, new TrustManager[]{new X509TrustManager() {
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                }}, null);
                hcb.sslContext(sc);
            } catch (Exception ignored) {}

            if (req.has("proxy") && req.get("proxy").isJsonObject()) {
                JsonObject p = req.getAsJsonObject("proxy");
                String host = p.get("host").getAsString();
                int pport = p.get("port").getAsInt();
                hcb.proxy(ProxySelector.of(new InetSocketAddress(host, pport)));
                if (p.has("user") && !p.get("user").isJsonNull()) {
                    String u = p.get("user").getAsString();
                    String pw = p.has("pass") && !p.get("pass").isJsonNull() ? p.get("pass").getAsString() : "";
                    hcb.authenticator(new java.net.Authenticator() {
                        @Override protected PasswordAuthentication getPasswordAuthentication() {
                            return new PasswordAuthentication(u, pw.toCharArray());
                        }
                    });
                }
            }

            java.net.http.HttpClient client = hcb.build();
            String sessionId = UUID.randomUUID().toString();
            Ws2Session session = new Ws2Session();
            StringBuilder textBuffer = new StringBuilder();

            java.net.http.WebSocket.Builder wsb = client.newWebSocketBuilder();
            // Add headers
            if (req.has("headers") && req.get("headers").isJsonArray()) {
                for (JsonElement el : req.getAsJsonArray("headers")) {
                    JsonArray pair = el.getAsJsonArray();
                    String hName = pair.get(0).getAsString();
                    // Skip restricted headers
                    if (!hName.equalsIgnoreCase("Host") && !hName.equalsIgnoreCase("Upgrade")
                            && !hName.equalsIgnoreCase("Connection") && !hName.equalsIgnoreCase("Sec-WebSocket-Key")
                            && !hName.equalsIgnoreCase("Sec-WebSocket-Version")) {
                        wsb.header(hName, pair.get(1).getAsString());
                    }
                }
            }
            // no subprotocols needed

            java.net.http.WebSocket ws = wsb.buildAsync(URI.create(url), new java.net.http.WebSocket.Listener() {
                @Override
                public CompletionStage<?> onText(java.net.http.WebSocket webSocket, CharSequence data, boolean last) {
                    textBuffer.append(data);
                    if (last) {
                        session.inbox.offer(textBuffer.toString());
                        textBuffer.setLength(0);
                    }
                    webSocket.request(1);
                    return null;
                }
                @Override
                public CompletionStage<?> onBinary(java.net.http.WebSocket webSocket, java.nio.ByteBuffer data, boolean last) {
                    byte[] bytes = new byte[data.remaining()];
                    data.get(bytes);
                    session.inbox.offer("__BIN__" + java.util.Base64.getEncoder().encodeToString(bytes));
                    webSocket.request(1);
                    return null;
                }
                @Override
                public CompletionStage<?> onClose(java.net.http.WebSocket webSocket, int statusCode, String reason) {
                    if (System.getenv("DEBUG_PROXY") != null) {
                        System.err.println("[ws2-closing] code=" + statusCode + " reason=" + reason);
                    }
                    session.closed = true;
                    session.closeCode = statusCode;
                    session.closeReason = reason;
                    session.inbox.offer("__WS_CLOSED__");
                    return null;
                }
                @Override
                public void onError(java.net.http.WebSocket webSocket, Throwable error) {
                    if (System.getenv("DEBUG_PROXY") != null) {
                        System.err.println("[ws2-error] " + error.getClass().getSimpleName() + ": " + error.getMessage());
                    }
                    session.closed = true;
                    session.inbox.offer("__WS_CLOSED__");
                }
                @Override
                public void onOpen(java.net.http.WebSocket webSocket) {
                    if (System.getenv("DEBUG_PROXY") != null) {
                        System.err.println("[ws2-open] connected");
                    }
                    webSocket.request(1);
                }
            }).get(timeout, TimeUnit.SECONDS);

            session.ws = ws;
            WS2_SESSIONS.put(sessionId, session);
            JsonObject out = new JsonObject();
            out.addProperty("id", sessionId);
            reply(exchange, 200, out.toString());
        } catch (Exception e) {
            JsonObject err = new JsonObject();
            err.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
            reply(exchange, 500, err.toString());
        }
    }

    private static void handleWs2Send(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { reply(exchange, 405, "{\"error\":\"POST only\"}"); return; }
        String raw; try (InputStream is = exchange.getRequestBody()) { raw = new String(readAll(is), StandardCharsets.UTF_8); }
        try {
            JsonObject req = JsonParser.parseString(raw).getAsJsonObject();
            String id = req.get("id").getAsString();
            String text = req.get("text").getAsString();
            Ws2Session session = WS2_SESSIONS.get(id);
            if (session == null) { reply(exchange, 404, "{\"error\":\"session not found\"}"); return; }
            if (session.closed) { reply(exchange, 410, "{\"error\":\"websocket closed\"}"); return; }
            if (System.getenv("DEBUG_PROXY") != null) {
                System.err.println("[ws2-send] len=" + text.length() + " data=" + text.substring(0, Math.min(text.length(), 120)));
            }
            boolean binary = req.has("binary") && req.get("binary").getAsBoolean();
            if (binary) {
                byte[] bytes = java.util.Base64.getDecoder().decode(text);
                session.ws.sendBinary(java.nio.ByteBuffer.wrap(bytes), true).get(10, TimeUnit.SECONDS);
            } else {
                session.ws.sendText(text, true).get(10, TimeUnit.SECONDS);
            }
            reply(exchange, 200, "{\"ok\":true}");
        } catch (Exception e) {
            JsonObject err = new JsonObject();
            err.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
            reply(exchange, 500, err.toString());
        }
    }

    private static void handleWs2Recv(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { reply(exchange, 405, "{\"error\":\"POST only\"}"); return; }
        String raw; try (InputStream is = exchange.getRequestBody()) { raw = new String(readAll(is), StandardCharsets.UTF_8); }
        try {
            JsonObject req = JsonParser.parseString(raw).getAsJsonObject();
            String id = req.get("id").getAsString();
            int timeout = req.has("timeout") ? req.get("timeout").getAsInt() : 10;
            Ws2Session session = WS2_SESSIONS.get(id);
            if (session == null) { reply(exchange, 404, "{\"error\":\"session not found\"}"); return; }
            String msg = session.inbox.poll(timeout, TimeUnit.SECONDS);
            if (msg == null) {
                reply(exchange, 200, "{\"error\":\"timeout\"}");
                return;
            }
            if ("__WS_CLOSED__".equals(msg)) {
                JsonObject out = new JsonObject();
                out.addProperty("closed", true);
                out.addProperty("code", session.closeCode);
                out.addProperty("reason", session.closeReason);
                reply(exchange, 200, out.toString());
                return;
            }
            JsonObject out = new JsonObject();
            out.addProperty("text", msg);
            reply(exchange, 200, out.toString());
        } catch (Exception e) {
            JsonObject err = new JsonObject();
            err.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
            reply(exchange, 500, err.toString());
        }
    }

    private static void handleWs2Close(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { reply(exchange, 405, "{\"error\":\"POST only\"}"); return; }
        String raw; try (InputStream is = exchange.getRequestBody()) { raw = new String(readAll(is), StandardCharsets.UTF_8); }
        try {
            JsonObject req = JsonParser.parseString(raw).getAsJsonObject();
            String id = req.get("id").getAsString();
            Ws2Session session = WS2_SESSIONS.remove(id);
            if (session != null && session.ws != null) {
                try { session.ws.sendClose(1000, "").get(5, TimeUnit.SECONDS); } catch (Exception ignored) {}
            }
            reply(exchange, 200, "{\"ok\":true}");
        } catch (Exception e) {
            JsonObject err = new JsonObject();
            err.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
            reply(exchange, 500, err.toString());
        }
    }
}
