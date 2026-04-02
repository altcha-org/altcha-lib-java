package org.altcha.altcha.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.altcha.altcha.v2.Altcha;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.security.SecureRandom;

/**
 * Minimal ALTCHA v2 example server.
 *
 * <p>Endpoints:</p>
 * <ul>
 *   <li>{@code GET  /challenge} – issues a signed v2 challenge in deterministic mode</li>
 *   <li>{@code POST /submit}    – verifies an ALTCHA payload from form data</li>
 * </ul>
 *
 * <p>Environment variables:</p>
 * <pre>
 *   HMAC_SECRET        Secret used to sign challenge parameters   (default: changeme-secret)
 *   HMAC_KEY_SECRET    Secret used to sign the derived key        (default: changeme-key-secret)
 *   CORS_ORIGIN        Value of Access-Control-Allow-Origin       (default: *)
 *   PORT               HTTP port to listen on                     (default: 3000)
 * </pre>
 *
 * <p>Run with {@code gradle :examples:server:run} from the project root.</p>
 */
public class Server {

    // -------------------------------------------------------------------------
    // Configuration (from environment)
    // -------------------------------------------------------------------------

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final String HMAC_SECRET = env("HMAC_SECRET", "changeme-secret");
    private static final String HMAC_KEY_SECRET  = env("HMAC_KEY_SECRET",  "changeme-key-secret");
    private static final String CORS_ORIGIN = env("CORS_ORIGIN", "*");
    private static final int    PORT        = Integer.parseInt(env("PORT", "3000"));

    /** SHA-iterative is fast and requires no external library. */
    private static final String ALGORITHM  = "PBKDF2/SHA-256";
    /** Number of hash iterations (work factor). */
    private static final int    COST       = 5_000;
    /**
     * Upper bound for the random counter.
     */
    private static final int    MAX_COUNTER = 10_000;
    /**
     * Lower bound for the random counter.
     */
    private static final int    MIN_COUNTER = 5_000;

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        var httpServer = HttpServer.create(new InetSocketAddress(PORT), 0);
        httpServer.createContext("/challenge", ex -> handleChallenge(ex, HMAC_SECRET, HMAC_KEY_SECRET));
        httpServer.createContext("/submit",    ex -> handleSubmit(ex, HMAC_SECRET, HMAC_KEY_SECRET));
        httpServer.setExecutor(Executors.newCachedThreadPool());
        httpServer.start();

        System.out.printf("ALTCHA example server listening on http://localhost:%d%n", PORT);
        System.out.printf("  GET  /challenge%n");
        System.out.printf("  POST /submit    (form field: altcha=<base64 payload>)%n");
    }

    // -------------------------------------------------------------------------
    // GET /challenge
    // -------------------------------------------------------------------------

    /**
     * Issues a new v2 challenge in deterministic mode.
     *
     * <p>A random counter is drawn from [MIN_COUNTER, MAX_COUNTER). The server derives the key
     * prefix from that counter and signs it with {@code HMAC_KEY_SECRET}. The client
     * brute-forces the counter until it reproduces the prefix; the server later
     * verifies the derived key via the key signature without re-running the KDF.</p>
     */
    private static void handleChallenge(HttpExchange ex, String hmacSecret, String keySecret)
            throws IOException {
        setCorsHeaders(ex);
        if (handlePreflight(ex)) return;
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, jsonError("Method not allowed"));
            return;
        }

        try {
            var counter = MIN_COUNTER + SECURE_RANDOM.nextInt(MAX_COUNTER - MIN_COUNTER);

            var opts = new Altcha.CreateChallengeOptions()
                    .algorithm(ALGORITHM)
                    .cost(COST)
                    .counter(counter)
                    .hmacSignatureSecret(hmacSecret)
                    .hmacKeySignatureSecret(keySecret);

            var challenge = Altcha.createChallenge(opts);

            send(ex, 200, challenge.toJson());
        } catch (Exception e) {
            send(ex, 500, jsonError(e.getMessage()));
        }
    }

    // -------------------------------------------------------------------------
    // POST /submit
    // -------------------------------------------------------------------------

    /**
     * Verifies an ALTCHA payload submitted as {@code application/x-www-form-urlencoded}.
     *
     * <p>Expected form field: {@code altcha=<base64-encoded JSON payload>}.</p>
     *
     * <p>Accepts both a client challenge solution and a Sentinel server-signature payload.
     * The payload type is detected automatically via {@link Altcha#isServerSignaturePayload}.</p>
     */
    private static void handleSubmit(HttpExchange ex, String hmacSecret, String keySecret)
            throws IOException {
        setCorsHeaders(ex);
        if (handlePreflight(ex)) return;
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, jsonError("Method not allowed"));
            return;
        }

        try {
            var body      = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            var altchaB64 = formField(body, "altcha");

            if (altchaB64 == null || altchaB64.isBlank()) {
                send(ex, 400, jsonError("Missing 'altcha' form field"));
                return;
            }

            boolean verified;
            String  altchaJson;
            if (Altcha.isServerSignaturePayload(altchaB64)) {
                // ALTCHA Sentinel server-signature payload
                var result = Altcha.verifyServerSignature(altchaB64, hmacSecret);
                verified   = result.verified();
                altchaJson = result.toJson();
            } else {
                // Client challenge solution — fast path via keySignature 
                var payload = Altcha.parsePayload(altchaB64);
                var result  = Altcha.verifySolution(
                        payload.challenge(), payload.solution(),
                        hmacSecret, keySecret, null);
                verified   = result.verified();
                altchaJson = result.toJson();
            }

            var status = verified ? 200 : 400;
            send(ex, status, "{\"altcha\":" + altchaJson + ",\"success\":" + verified + "}");
        } catch (Exception e) {
            send(ex, 400, jsonError(e.getMessage()));
        }
    }

    // -------------------------------------------------------------------------
    // HTTP helpers
    // -------------------------------------------------------------------------

    private static void setCorsHeaders(HttpExchange ex) {
        var h = ex.getResponseHeaders();
        h.set("Access-Control-Allow-Origin",  CORS_ORIGIN);
        h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        h.set("Access-Control-Allow-Headers", "Content-Type");
    }

    /** Handles CORS preflight. Returns {@code true} if the exchange was a preflight. */
    private static boolean handlePreflight(HttpExchange ex) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
            ex.sendResponseHeaders(204, -1);
            ex.close();
            return true;
        }
        return false;
    }

    private static void send(HttpExchange ex, int status, String body) throws IOException {
        var bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        try (var out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }

    // -------------------------------------------------------------------------
    // Misc helpers
    // -------------------------------------------------------------------------

    /** Extracts a single field value from a URL-encoded form body. */
    private static String formField(String body, String name) throws Exception {
        for (var pair : body.split("&")) {
            var kv = pair.split("=", 2);
            if (kv.length == 2
                    && URLDecoder.decode(kv[0], StandardCharsets.UTF_8).equals(name)) {
                return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static String jsonError(String message) {
        return "{\"error\":" + jsonString(message) + "}";
    }

    private static String jsonString(String s) {
        var sb = new StringBuilder(s.length() + 2).append('"');
        for (var i = 0; i < s.length(); i++) {
            var c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> { if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c); }
            }
        }
        return sb.append('"').toString();
    }

    private static String env(String name, String fallback) {
        var val = System.getenv(name);
        return (val != null && !val.isBlank()) ? val : fallback;
    }
}
