package org.altcha.altcha.v2;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/**
 * ALTCHA v2 – key-derivation-based proof-of-work.
 *
 * <p>Unlike v1 (simple hash), v2 uses configurable KDFs (PBKDF2, SHA-iterative)
 * to derive a key from {@code nonce || counter} and verifies that the result
 * starts with a required {@code keyPrefix}. Challenge parameters are signed with
 * HMAC to prevent tampering.</p>
 *
 * <h2>Supported algorithms (built-in)</h2>
 * <ul>
 *   <li>{@code "PBKDF2/SHA-256"}, {@code "PBKDF2/SHA-384"}, {@code "PBKDF2/SHA-512"}</li>
 *   <li>{@code "SHA-256"}, {@code "SHA-384"}, {@code "SHA-512"} (iterative hashing)</li>
 * </ul>
 * <p>External KDFs (Argon2id, Scrypt) can be plugged in via {@link KeyDerivationFunction}.</p>
 */
public final class Altcha {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static final int    DEFAULT_KEY_LENGTH   = 32;
    public static final String DEFAULT_KEY_PREFIX   = "00";
    public static final String DEFAULT_HMAC_ALGORITHM = "SHA-256";
    /** Default {@link #solveChallenge} timeout, as in the JS library. */
    public static final Duration DEFAULT_SOLVE_TIMEOUT = Duration.ofSeconds(90);

    private Altcha() {}

    // -------------------------------------------------------------------------
    // Data types (records)
    // -------------------------------------------------------------------------

    /**
     * The parameters embedded in a v2 challenge.
     *
     * <p>Optional fields are {@code null} when absent. The canonical-JSON
     * serialisation (used for signing) excludes {@code null} fields.</p>
     */
    public record ChallengeParameters(
            String algorithm,
            String nonce,
            String salt,
            int cost,
            int keyLength,
            String keyPrefix,
            String keySignature,   // nullable – set in deterministic mode
            Integer memoryCost,    // nullable – Argon2id / Scrypt
            Integer parallelism,   // nullable – Argon2id / Scrypt
            Number expiresAt,      // nullable – unix timestamp (seconds); Long, or Double if fractional (as in JS)
            Map<String, Object> data // nullable – arbitrary metadata
    ) {
        public ChallengeParameters withKeyPrefix(String newKeyPrefix) {
            return new ChallengeParameters(algorithm, nonce, salt, cost, keyLength,
                    newKeyPrefix, keySignature, memoryCost, parallelism, expiresAt, data);
        }

        public ChallengeParameters withKeySignature(String newKeySignature) {
            return new ChallengeParameters(algorithm, nonce, salt, cost, keyLength,
                    keyPrefix, newKeySignature, memoryCost, parallelism, expiresAt, data);
        }
    }

    /** A v2 challenge object: parameters + optional HMAC signature. */
    public record Challenge(ChallengeParameters parameters, String signature) {
        /**
         * Serialises this challenge to JSON.
         *
         * <p>The JSON structure matches what the ALTCHA widget expects:</p>
         * <pre>{@code
         * {
         *   "parameters": { "algorithm": "...", "cost": 5000, ... },
         *   "signature":  "hex..."
         * }
         * }</pre>
         */
        public String toJson() {
            var params = new TreeMap<String, Object>();
            params.put("algorithm",  parameters.algorithm());
            params.put("cost",       parameters.cost());
            if (parameters.data()         != null) params.put("data",         parameters.data());
            if (parameters.expiresAt()    != null) params.put("expiresAt",    parameters.expiresAt());
            params.put("keyLength",  parameters.keyLength());
            params.put("keyPrefix",  parameters.keyPrefix());
            if (parameters.keySignature() != null) params.put("keySignature", parameters.keySignature());
            if (parameters.memoryCost()   != null) params.put("memoryCost",   parameters.memoryCost());
            params.put("nonce",      parameters.nonce());
            if (parameters.parallelism()  != null) params.put("parallelism",  parameters.parallelism());
            params.put("salt",       parameters.salt());

            var root = new TreeMap<String, Object>();
            root.put("parameters", params);
            if (signature != null) root.put("signature", signature);
            return encodeValue(root);
        }
    }

    /** The solution found by brute-forcing counter values; {@code time} in ms (1 decimal, like JS). */
    public record Solution(long counter, String derivedKey, Double time) {}

    /** Full v2 payload sent from the client after solving. */
    public record Payload(Challenge challenge, Solution solution) {}

    /** Structured result returned by {@link #verifySolution}; {@code time} in ms (1 decimal, like JS). */
    public record VerifySolutionResult(
            boolean verified,
            boolean expired,
            Boolean invalidSignature,  // null when expired before checking
            Boolean invalidSolution,   // null when signature was invalid
            double time) {

        /** Serialises this result to a JSON object string, with the same fields as the JS result. */
        public String toJson() {
            return "{\"expired\":" + expired
                    + ",\"invalidSignature\":" + invalidSignature
                    + ",\"invalidSolution\":" + invalidSolution
                    + ",\"time\":" + jsNumber(time)
                    + ",\"verified\":" + verified + "}";
        }
    }

    /** Signed server-attestation payload from the ALTCHA Sentinel service. */
    public record ServerSignaturePayload(
            String algorithm,
            String apiKey,
            String id,
            String verificationData,
            String signature,
            boolean verified) {}

    /** Result of verifying a server-attestation payload, with the same fields as the JS result. */
    public record ServerSignatureVerification(
            boolean verified,
            boolean expired,
            boolean invalidSignature,
            boolean invalidSolution,
            double time,                                         // ms, 1 decimal
            ServerSignatureVerificationData verificationData) { // null if the payload was incomplete

        /** Serialises this result to a JSON object string, matching the JS result. */
        public String toJson() {
            return "{\"expired\":" + expired
                    + ",\"invalidSignature\":" + invalidSignature
                    + ",\"invalidSolution\":" + invalidSolution
                    + ",\"time\":" + jsNumber(time)
                    + ",\"verificationData\":" + (verificationData != null ? verificationData.toJson() : "null")
                    + ",\"verified\":" + verified + "}";
        }
    }

    /**
     * Verification data from the ALTCHA Sentinel service, parsed and typed like JS
     * {@code parseVerificationData}: {@code true}/{@code false} → {@code Boolean}; digits →
     * {@code Long} ({@code Double} beyond 15 digits); digits.digits → {@code Double}; anything
     * else → trimmed {@code String}, except non-empty {@code fields}/{@code reasons} →
     * {@code List<String>}. {@link #values()} holds every entry, in JS property order.
     */
    public record ServerSignatureVerificationData(Map<String, Object> values) {

        /** The parsed value of {@code name}, or {@code null} if absent. */
        public Object get(String name)  { return values.get(name); }

        public String classification()  { return string("classification"); }
        public String email()           { return string("email"); }
        public String fieldsHash()      { return string("fieldsHash"); }
        public String id()              { return string("id"); }
        public String ipAddress()       { return string("ipAddress"); }
        /** {@code null} if absent or not a number. */
        public Number expire()          { return number("expire"); }
        /** {@code null} if absent or not a number. */
        public Number score()           { return number("score"); }
        /** {@code null} if absent or not a number. */
        public Number time()            { return number("time"); }
        /** {@code true} only for {@code verified=true}. */
        public boolean verified()       { return Boolean.TRUE.equals(values.get("verified")); }
        /** Empty if absent or empty. */
        public List<String> fields()    { return list("fields"); }
        /** Empty if absent or empty. */
        public List<String> reasons()   { return list("reasons"); }

        /** Serialises the data like JS {@code JSON.stringify(parseVerificationData(…))}. */
        public String toJson() {
            var sb = new StringBuilder();
            encodeValue(sb, values, false);
            return sb.toString();
        }

        private String string(String name) {
            var v = values.get(name);
            return v == null ? null : v instanceof Number n ? jsNumber(n) : v.toString();
        }

        private Number number(String name) {
            return values.get(name) instanceof Number n ? n : null;
        }

        @SuppressWarnings("unchecked")
        private List<String> list(String name) {
            var v = values.get(name);
            if (v instanceof List<?> l) return (List<String>) l;
            return v == null || "".equals(v) ? List.of() : List.of(string(name));
        }
    }

    // -------------------------------------------------------------------------
    // Key derivation interface
    // -------------------------------------------------------------------------

    /**
     * Result returned by a {@link KeyDerivationFunction}.
     *
     * <p>{@code parameters} is optional. When non-null, {@link #createChallenge} uses it in place
     * of the challenge parameters before computing the key prefix and signing, so a KDF can
     * add or adjust signed parameters (like JS {@code Object.assign(parameters, result.parameters)}).
     * Return the parameters you received with the fields you want changed. Solve and verify
     * ignore it, as in JS.</p>
     */
    public record DeriveKeyResult(byte[] derivedKey, ChallengeParameters parameters) {
        public DeriveKeyResult(byte[] derivedKey) {
            this(derivedKey, null);
        }
    }

    /**
     * Pluggable key derivation function.
     *
     * <p>Built-in implementations are obtained via {@link #kdf(String)}.</p>
     */
    @FunctionalInterface
    public interface KeyDerivationFunction {
        DeriveKeyResult deriveKey(ChallengeParameters parameters, byte[] salt, byte[] password)
                throws Exception;
    }

    // -------------------------------------------------------------------------
    // PasswordBuffer – combines nonce + counter into a single byte array
    // -------------------------------------------------------------------------

    /**
     * How the counter is appended to the nonce to form the KDF password. Not signed: creator,
     * solver and verifier must use the same mode.
     */
    public enum CounterMode {
        /** Big-endian 32-bit unsigned integer (v2 default). */
        UINT32,
        /** Decimal string, UTF-8 encoded, like JS {@code counter.toString()} (v1 compatibility). */
        STRING
    }

    /**
     * Manages the password buffer passed to the KDF for each counter iteration.
     *
     * <p>In {@link CounterMode#UINT32} mode the counter is appended to the nonce as a
     * big-endian 32-bit unsigned integer (its low 32 bits, like JS {@code DataView.setUint32}),
     * and the returned array from {@link #setCounter} is a view of an internal buffer – do not
     * retain a reference across iterations. In {@link CounterMode#STRING} mode the nonce is
     * followed by the counter's decimal digits and each call returns a new array.</p>
     */
    public static final class PasswordBuffer {
        private final byte[] nonce;
        private final byte[] buffer;
        private final CounterMode mode;

        public PasswordBuffer(byte[] nonce) {
            this(nonce, CounterMode.UINT32);
        }

        /** {@code mode} {@code null} means {@link CounterMode#UINT32}. */
        public PasswordBuffer(byte[] nonce, CounterMode mode) {
            this.nonce  = nonce;
            this.mode   = mode != null ? mode : CounterMode.UINT32;
            this.buffer = this.mode == CounterMode.UINT32 ? Arrays.copyOf(nonce, nonce.length + 4) : null;
        }

        /** Returns the nonce+counter password for counter {@code n}. */
        public byte[] setCounter(long n) {
            if (mode == CounterMode.STRING) {
                var digits = jsNumber(n);  // JS Number#toString; ASCII only
                var out    = Arrays.copyOf(nonce, nonce.length + digits.length());
                for (var i = 0; i < digits.length(); i++) out[nonce.length + i] = (byte) digits.charAt(i);
                return out;
            }
            buffer[nonce.length]     = (byte) (n >>> 24);
            buffer[nonce.length + 1] = (byte) (n >>> 16);
            buffer[nonce.length + 2] = (byte) (n >>> 8);
            buffer[nonce.length + 3] = (byte)  n;
            return buffer;
        }
    }

    // -------------------------------------------------------------------------
    // CreateChallengeOptions (mutable builder)
    // -------------------------------------------------------------------------

    public static final class CreateChallengeOptions {
        public String algorithm;
        public Long counter;
        public CounterMode counterMode = CounterMode.UINT32;
        public int cost;
        public Map<String, Object> data;
        public KeyDerivationFunction deriveKey;
        public Number expiresAt;
        public String hmacAlgorithm = DEFAULT_HMAC_ALGORITHM;
        public String hmacKeySignatureSecret;
        public String hmacSignatureSecret;
        public int keyLength = DEFAULT_KEY_LENGTH;
        public String keyPrefix = DEFAULT_KEY_PREFIX;
        public Integer keyPrefixLength;
        public Integer memoryCost;
        public Integer parallelism;

        public CreateChallengeOptions algorithm(String v)                  { algorithm = v; return this; }
        public CreateChallengeOptions counter(long v)                      { counter = v; return this; }
        public CreateChallengeOptions counterMode(CounterMode v)           { counterMode = v; return this; }
        public CreateChallengeOptions cost(int v)                          { cost = v; return this; }
        public CreateChallengeOptions data(Map<String, Object> v)          { data = v; return this; }
        public CreateChallengeOptions deriveKey(KeyDerivationFunction v)   { deriveKey = v; return this; }
        public CreateChallengeOptions expiresAt(Number v)                  { expiresAt = v; return this; }
        public CreateChallengeOptions expiresInSeconds(long seconds)       { expiresAt = System.currentTimeMillis() / 1000 + seconds; return this; }
        public CreateChallengeOptions hmacAlgorithm(String v)              { hmacAlgorithm = v; return this; }
        public CreateChallengeOptions hmacKeySignatureSecret(String v)     { hmacKeySignatureSecret = v; return this; }
        public CreateChallengeOptions hmacSignatureSecret(String v)        { hmacSignatureSecret = v; return this; }
        public CreateChallengeOptions keyLength(int v)                     { keyLength = v; return this; }
        public CreateChallengeOptions keyPrefix(String v)                  { keyPrefix = v; return this; }
        public CreateChallengeOptions keyPrefixLength(Integer v)           { keyPrefixLength = v; return this; }
        public CreateChallengeOptions memoryCost(Integer v)                { memoryCost = v; return this; }
        public CreateChallengeOptions parallelism(Integer v)               { parallelism = v; return this; }
    }

    // -------------------------------------------------------------------------
    // Built-in key derivation functions
    // -------------------------------------------------------------------------

    /**
     * Returns the built-in KDF for the given algorithm string.
     *
     * @throws IllegalArgumentException for unsupported algorithms
     */
    public static KeyDerivationFunction kdf(String algorithm) {
        return switch (algorithm) {
            case "PBKDF2/SHA-256", "PBKDF2/SHA-384", "PBKDF2/SHA-512" -> pbkdf2();
            case "SHA-256", "SHA-384", "SHA-512"                       -> sha();
            default -> throw new IllegalArgumentException("No built-in KDF for algorithm: " + algorithm);
        };
    }

    /** PBKDF2-based KDF. Uses a standards-compliant manual implementation for cross-platform compatibility. */
    public static KeyDerivationFunction pbkdf2() {
        return (params, salt, password) -> {
            var hmacName = switch (params.algorithm()) {
                case "PBKDF2/SHA-512" -> "HmacSHA512";
                case "PBKDF2/SHA-384" -> "HmacSHA384";
                default               -> "HmacSHA256";
            };
            var dk = pbkdf2Hmac(hmacName, password, salt, params.cost(), params.keyLength());
            return new DeriveKeyResult(dk);
        };
    }

    /** SHA-iterative KDF: repeatedly hashes {@code salt || password} for {@code cost} rounds. */
    public static KeyDerivationFunction sha() {
        return (params, salt, password) -> {
            var digestName = switch (params.algorithm()) {
                case "SHA-512" -> "SHA-512";
                case "SHA-384" -> "SHA-384";
                default        -> "SHA-256";
            };
            var iterations  = Math.max(1, params.cost());
            var md = MessageDigest.getInstance(digestName);
            byte[] derived  = null;
            for (var i = 0; i < iterations; i++) {
                md.reset();
                if (i == 0) { md.update(salt); md.update(password); }
                else          md.update(derived);
                derived = md.digest();
            }
            return new DeriveKeyResult(jsSlice(derived, params.keyLength()));
        };
    }

    // -------------------------------------------------------------------------
    // Challenge creation
    // -------------------------------------------------------------------------

    /**
     * Creates a new v2 proof-of-work challenge.
     *
     * <p>If {@link CreateChallengeOptions#counter} is set, the KDF is invoked once
     * (with {@link CreateChallengeOptions#counterMode}), parameters it returns replace the
     * challenge parameters, and the first {@code keyPrefixLength} bytes of the derived key
     * become the {@code keyPrefix} (deterministic mode). Otherwise a static prefix (default
     * {@code "00"}) is used and the client must brute-force the counter.</p>
     *
     * <p>If {@link CreateChallengeOptions#hmacSignatureSecret} is set (non-empty), the
     * challenge parameters are HMAC-signed and the returned {@link Challenge}
     * includes a {@code signature}.</p>
     */
    public static Challenge createChallenge(CreateChallengeOptions options) throws Exception {
        var nonce = bytesToHex(randomBytes(16));
        var salt  = bytesToHex(randomBytes(16));
        var prefixLength = options.keyPrefixLength != null ? options.keyPrefixLength : options.keyLength / 2;

        var params = new ChallengeParameters(
                options.algorithm,
                nonce,
                salt,
                options.cost,
                options.keyLength,
                options.keyPrefix,
                null,
                options.memoryCost,
                options.parallelism,
                options.expiresAt,
                options.data);

        byte[] derivedKey = null;

        if (options.counter != null) {
            var kdfFn    = options.deriveKey != null ? options.deriveKey : kdf(options.algorithm);
            var nonceBuf = hexToBytes(nonce);
            var saltBuf  = hexToBytes(salt);
            var pw       = new PasswordBuffer(nonceBuf, options.counterMode);
            var result   = kdfFn.deriveKey(params, saltBuf, pw.setCounter(options.counter));
            derivedKey   = result.derivedKey();
            if (result.parameters() != null) params = result.parameters();
            params       = params.withKeyPrefix(bytesToHex(jsSlice(derivedKey, prefixLength)));
        }

        if (!isSet(options.hmacSignatureSecret)) {
            return new Challenge(params, null);
        }

        return signChallenge(options.hmacAlgorithm, params, derivedKey,
                options.hmacSignatureSecret, options.hmacKeySignatureSecret);
    }

    /** Signs challenge parameters with HMAC. Optionally also signs the derived key. */
    public static Challenge signChallenge(String hmacAlgorithm, ChallengeParameters params,
            byte[] derivedKey, String hmacSignatureSecret, String hmacKeySignatureSecret)
            throws Exception {
        if (derivedKey != null && isSet(hmacKeySignatureSecret)) {
            params = params.withKeySignature(hmacHex(hmacAlgorithm, derivedKey, hmacKeySignatureSecret));
        }
        var signature = hmacHex(hmacAlgorithm,
                canonicalJson(params).getBytes(StandardCharsets.UTF_8),
                hmacSignatureSecret);
        return new Challenge(params, signature);
    }

    // -------------------------------------------------------------------------
    // Challenge solving (client-side utility)
    // -------------------------------------------------------------------------

    /**
     * Brute-forces counter values until the derived key starts with the required prefix.
     *
     * <p>Like the JS library, gives up after {@code timeout} (checked every 10 attempts)
     * and returns {@code null}. To abort a running solve, interrupt its thread
     * (e.g. {@code Future.cancel(true)}).</p>
     *
     * @param challenge    the challenge to solve
     * @param kdfFn        the KDF to use (must match the algorithm in the challenge)
     * @param counterStart starting counter value (0 for a fresh solve)
     * @param counterStep  increment between attempts (1 for single-threaded)
     * @param timeout      maximum solving time; {@code null} or zero means no timeout
     * @param counterMode  counter encoding; must match the creator's ({@code null} means
     *                     {@link CounterMode#UINT32})
     * @return the solution, or {@code null} if the timeout elapsed first
     * @throws InterruptedException if the calling thread is interrupted
     */
    public static Solution solveChallenge(Challenge challenge, KeyDerivationFunction kdfFn,
            long counterStart, long counterStep, Duration timeout, CounterMode counterMode) throws Exception {
        var params        = challenge.parameters();
        var nonceBuf      = hexToBytes(params.nonce());
        var saltBuf       = hexToBytes(params.salt());
        var keyPrefix     = params.keyPrefix();
        var keyPrefixBuf  = keyPrefixBytes(keyPrefix);
        var pw            = new PasswordBuffer(nonceBuf, counterMode);
        var timeoutNanos  = timeout == null ? 0 : TimeUnit.NANOSECONDS.convert(timeout);
        var t0            = System.nanoTime();
        var counter       = counterStart;

        for (var iterations = 0L; ; iterations++) {
            if (Thread.interrupted()) throw new InterruptedException("solveChallenge interrupted");
            if (timeoutNanos != 0 && iterations % 10 == 0 && System.nanoTime() - t0 > timeoutNanos) return null;
            var derivedKey = kdfFn.deriveKey(params, saltBuf, pw.setCounter(counter)).derivedKey();
            if (keyPrefixMatches(derivedKey, keyPrefix, keyPrefixBuf)) {
                return new Solution(counter, bytesToHex(derivedKey), elapsed(t0));
            }
            counter += counterStep;
        }
    }

    /** Solves with {@link CounterMode#UINT32}; returns {@code null} on timeout. */
    public static Solution solveChallenge(Challenge challenge, KeyDerivationFunction kdfFn,
            long counterStart, long counterStep, Duration timeout) throws Exception {
        return solveChallenge(challenge, kdfFn, counterStart, counterStep, timeout, CounterMode.UINT32);
    }

    /** Solves with custom start/step and {@link #DEFAULT_SOLVE_TIMEOUT}; returns {@code null} on timeout. */
    public static Solution solveChallenge(Challenge challenge, KeyDerivationFunction kdfFn,
            long counterStart, long counterStep) throws Exception {
        return solveChallenge(challenge, kdfFn, counterStart, counterStep, DEFAULT_SOLVE_TIMEOUT);
    }

    /** Starts at counter 0, step 1, with {@link #DEFAULT_SOLVE_TIMEOUT}; returns {@code null} on timeout. */
    public static Solution solveChallenge(Challenge challenge, KeyDerivationFunction kdfFn)
            throws Exception {
        return solveChallenge(challenge, kdfFn, 0, 1, DEFAULT_SOLVE_TIMEOUT);
    }

    // -------------------------------------------------------------------------
    // Solution verification
    // -------------------------------------------------------------------------

    /**
     * Verifies a v2 solution against the original challenge.
     *
     * <p>Verification steps (in order):</p>
     * <ol>
     *   <li>Expiry check – if {@code expiresAt} is set and has passed.</li>
     *   <li>Signature presence – the challenge must be signed.</li>
     *   <li>Signature validity – HMAC of canonical-JSON of parameters.</li>
     *   <li>Key check – either via {@code keySignature} (fast) or by re-deriving.</li>
     * </ol>
     *
     * @param challenge            the original challenge (as received from / sent to client)
     * @param solution             the solution submitted by the client
     * @param hmacSignatureSecret     the secret used when the challenge was signed (required)
     * @param hmacKeySignatureSecret  optional secret for fast key-signature verification
     * @param hmacAlgorithm           HMAC algorithm used when the challenge was signed: a WebCrypto
     *                                hash name ({@code "SHA-256"}, {@code "SHA-384"}, {@code "SHA-512"}
     *                                or {@code "SHA-1"}, case-insensitive; others throw);
     *                                {@code null} means {@link #DEFAULT_HMAC_ALGORITHM}
     * @param counterMode             counter encoding used when re-deriving; must match the
     *                                creator's ({@code null} means {@link CounterMode#UINT32})
     * @param kdfFn                   KDF to use when re-deriving (may be {@code null} if
     *                                {@code keySignature} is present)
     */
    public static VerifySolutionResult verifySolution(
            Challenge challenge,
            Solution solution,
            String hmacSignatureSecret,
            String hmacKeySignatureSecret,
            String hmacAlgorithm,
            CounterMode counterMode,
            KeyDerivationFunction kdfFn) throws Exception {

        if (!isSet(hmacSignatureSecret)) {
            throw new IllegalArgumentException("hmacSignatureSecret is required for v2 verification");
        }

        var t0     = System.nanoTime();
        var params = challenge.parameters();

        // 1. Expiry (against fractional seconds, like JS `expiresAt && expiresAt < Date.now() / 1000`; 0 = no expiry)
        var expiresAt = params.expiresAt() != null ? params.expiresAt().doubleValue() : 0;
        if (expiresAt != 0 && expiresAt < System.currentTimeMillis() / 1000.0) {
            return new VerifySolutionResult(false, true, null, null, elapsed(t0));
        }

        // 2. Signature present
        if (challenge.signature() == null || challenge.signature().isBlank()) {
            return new VerifySolutionResult(false, false, true, null, elapsed(t0));
        }

        // 3. Verify challenge signature
        if (hmacAlgorithm == null) hmacAlgorithm = DEFAULT_HMAC_ALGORITHM;
        var expectedSig = hmacHex(hmacAlgorithm,
                canonicalJson(params).getBytes(StandardCharsets.UTF_8),
                hmacSignatureSecret);
        if (!constantTimeEqual(challenge.signature(), expectedSig)) {
            return new VerifySolutionResult(false, false, true, null, elapsed(t0));
        }

        // 4a. Fast path: key signature
        if (isSet(params.keySignature()) && isSet(hmacKeySignatureSecret)) {
            // Client-controlled: malformed hex is an invalid solution, not an exception.
            if (!isHex(solution.derivedKey())) {
                return new VerifySolutionResult(false, false, false, true, elapsed(t0));
            }
            var derivedKeyBytes = hexToBytes(solution.derivedKey());
            var expectedKeySig  = hmacHex(hmacAlgorithm, derivedKeyBytes, hmacKeySignatureSecret);
            var valid = constantTimeEqual(params.keySignature(), expectedKeySig);
            return new VerifySolutionResult(valid, false, false, !valid, elapsed(t0));
        }

        // 4b. Re-derive and compare
        if (kdfFn == null) {
            throw new IllegalArgumentException(
                    "kdfFn is required when no keySignature is present in the challenge");
        }
        if (solution.derivedKey() == null) {
            return new VerifySolutionResult(false, false, false, true, elapsed(t0));
        }
        var nonceBuf = hexToBytes(params.nonce());
        var saltBuf  = hexToBytes(params.salt());
        var pw       = new PasswordBuffer(nonceBuf, counterMode);
        var derivedKey    = kdfFn.deriveKey(params, saltBuf, pw.setCounter(solution.counter())).derivedKey();
        var keyMatches    = constantTimeEqual(bytesToHex(derivedKey), solution.derivedKey());
        var prefixMatches = keyPrefixMatches(derivedKey, params.keyPrefix(), keyPrefixBytes(params.keyPrefix()));
        var valid         = keyMatches && prefixMatches;
        return new VerifySolutionResult(valid, false, false, !valid, elapsed(t0));
    }

    /** Verifies with {@link CounterMode#UINT32}. */
    public static VerifySolutionResult verifySolution(
            Challenge challenge, Solution solution,
            String hmacSignatureSecret, String hmacKeySignatureSecret,
            String hmacAlgorithm, KeyDerivationFunction kdfFn) throws Exception {
        return verifySolution(challenge, solution, hmacSignatureSecret, hmacKeySignatureSecret,
                hmacAlgorithm, CounterMode.UINT32, kdfFn);
    }

    /** Convenience overload using {@link #DEFAULT_HMAC_ALGORITHM}. */
    public static VerifySolutionResult verifySolution(
            Challenge challenge, Solution solution,
            String hmacSignatureSecret, String hmacKeySignatureSecret,
            KeyDerivationFunction kdfFn) throws Exception {
        return verifySolution(challenge, solution, hmacSignatureSecret, hmacKeySignatureSecret, null, kdfFn);
    }

    /** Convenience overload with no key-signature secret, using {@link #DEFAULT_HMAC_ALGORITHM}. */
    public static VerifySolutionResult verifySolution(
            Challenge challenge, Solution solution,
            String hmacSignatureSecret, KeyDerivationFunction kdfFn) throws Exception {
        return verifySolution(challenge, solution, hmacSignatureSecret, null, null, kdfFn);
    }

    // -------------------------------------------------------------------------
    // Base64 payload parsing (server-side ingestion of client submissions)
    // -------------------------------------------------------------------------

    /**
     * Decodes a base64-encoded v2 JSON payload submitted by the client.
     *
     * <p>Expected structure:
     * <pre>{@code
     * {
     *   "challenge": {
     *     "parameters": { "algorithm": "...", "nonce": "...", ... },
     *     "signature": "..."
     *   },
     *   "solution": { "counter": 42, "derivedKey": "..." }
     * }
     * }</pre>
     * </p>
     */
    public static Payload parsePayload(String base64Payload) throws Exception {
        // Parsed with insertion order preserved: canonical JSON keeps the key order of objects inside arrays.
        var rootMap     = asObject(parseBase64Json(base64Payload), "payload");
        var challengeMap = asObject(rootMap.get("challenge"), "challenge");
        var paramsMap   = asObject(challengeMap.get("parameters"), "parameters");
        var solutionMap = asObject(rootMap.get("solution"), "solution");

        var params = new ChallengeParameters(
                requiredString(paramsMap, "algorithm"),
                requiredString(paramsMap, "nonce"),
                requiredString(paramsMap, "salt"),
                requiredNumber(paramsMap, "cost", Integer::parseInt, Number::intValue),
                requiredNumber(paramsMap, "keyLength", Integer::parseInt, Number::intValue),
                requiredString(paramsMap, "keyPrefix"),
                optionalString(paramsMap, "keySignature"),
                paramsMap.get("memoryCost") != null ? requiredNumber(paramsMap, "memoryCost", Integer::parseInt, Number::intValue) : null,
                paramsMap.get("parallelism") != null ? requiredNumber(paramsMap, "parallelism", Integer::parseInt, Number::intValue) : null,
                paramsMap.get("expiresAt") != null ? jsonNumber(paramsMap.get("expiresAt"), "expiresAt") : null,
                paramsMap.get("data") != null ? asObject(paramsMap.get("data"), "data") : null);

        var challenge = new Challenge(params, optionalString(challengeMap, "signature"));
        var solution  = new Solution(
                requiredNumber(solutionMap, "counter", Long::parseLong, Number::longValue),
                requiredString(solutionMap, "derivedKey"),
                solutionMap.get("time") != null ? requiredNumber(solutionMap, "time", Double::parseDouble, Number::doubleValue) : null);

        return new Payload(challenge, solution);
    }

    /**
     * Returns {@code true} if the base64 payload is a server-signature payload
     * (from the ALTCHA Sentinel service) rather than a client challenge solution.
     *
     * <p>Detection is based on the presence of a {@code verificationData} field in the
     * decoded JSON — client payloads have a nested {@code challenge} object instead.</p>
     */
    public static boolean isServerSignaturePayload(String base64Payload) {
        try {
            return parseBase64Json(base64Payload) instanceof Map<?, ?> json && json.containsKey("verificationData");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Decodes and verifies a base64-encoded v2 payload in one call.
     *
     * @see #parsePayload(String)
     * @see #verifySolution(Challenge, Solution, String, KeyDerivationFunction)
     */
    public static VerifySolutionResult verifySolution(String base64Payload,
            String hmacSignatureSecret, KeyDerivationFunction kdfFn) throws Exception {
        return verifySolution(base64Payload, hmacSignatureSecret, null, kdfFn);
    }

    /**
     * Decodes and verifies a base64-encoded v2 payload, using the key-signature fast path when
     * the challenge has a {@code keySignature} and {@code hmacKeySignatureSecret} is set.
     *
     * @see #verifySolution(Challenge, Solution, String, String, KeyDerivationFunction)
     */
    public static VerifySolutionResult verifySolution(String base64Payload,
            String hmacSignatureSecret, String hmacKeySignatureSecret, KeyDerivationFunction kdfFn)
            throws Exception {
        return verifySolution(base64Payload, hmacSignatureSecret, hmacKeySignatureSecret, null, null, kdfFn);
    }

    /**
     * Decodes and verifies a base64-encoded v2 payload with an explicit HMAC algorithm and
     * counter mode; both must match the options the challenge was created with
     * ({@code null} means {@link #DEFAULT_HMAC_ALGORITHM} / {@link CounterMode#UINT32}).
     *
     * @see #verifySolution(Challenge, Solution, String, String, String, CounterMode, KeyDerivationFunction)
     */
    public static VerifySolutionResult verifySolution(String base64Payload,
            String hmacSignatureSecret, String hmacKeySignatureSecret, String hmacAlgorithm,
            CounterMode counterMode, KeyDerivationFunction kdfFn) throws Exception {
        var payload = parsePayload(base64Payload);
        return verifySolution(payload.challenge(), payload.solution(),
                hmacSignatureSecret, hmacKeySignatureSecret, hmacAlgorithm, counterMode, kdfFn);
    }

    // -------------------------------------------------------------------------
    // Fields hash verification (Sentinel service)
    // -------------------------------------------------------------------------

    public static boolean verifyFieldsHash(Map<String, String> formData, String[] fields,
            String fieldsHash, String algorithm) throws Exception {
        var sb = new StringBuilder();
        for (var field : fields) {
            var value = formData.get(field);
            if (value != null) sb.append(value);
            sb.append('\n');
        }
        var digest = MessageDigest.getInstance(algorithm);
        var hash = digest.digest(sb.toString().trim().getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash).equals(fieldsHash);
    }

    // -------------------------------------------------------------------------
    // Server signature verification (Sentinel service)
    // -------------------------------------------------------------------------

    /**
     * Verifies a Sentinel server-signature payload like JS {@code verifyServerSignature}.
     * If {@code algorithm}, {@code verificationData} or {@code signature} is missing, returns a
     * result with every check failed and no verification data.
     */
    public static ServerSignatureVerification verifyServerSignature(
            ServerSignaturePayload payload, String hmacKey) throws Exception {
        var t0 = System.nanoTime();
        if (payload.algorithm() == null || payload.verificationData() == null || payload.signature() == null) {
            return new ServerSignatureVerification(false, false, true, true, elapsed(t0), null);
        }
        var hash      = MessageDigest.getInstance(webCryptoHash(payload.algorithm()))
                .digest(utf8(payload.verificationData()));
        var signature = hmacHex(payload.algorithm(), hash, hmacKey);
        var verData   = parseVerificationData(payload.verificationData());
        var expire    = verData.get("expire");
        // JS: !!expire && expire < Math.floor(Date.now() / 1000), with JS truthiness and number coercion
        var expired          = jsTruthy(expire) && jsToNumber(expire) < System.currentTimeMillis() / 1000;
        var invalidSignature = !constantTimeEqual(payload.signature(), signature);
        var invalidSolution  = !verData.verified() || !payload.verified();
        return new ServerSignatureVerification(!expired && !invalidSignature && !invalidSolution,
                expired, invalidSignature, invalidSolution, elapsed(t0), verData);
    }

    /** Decodes and verifies a base64-encoded Sentinel server-signature payload. */
    public static ServerSignatureVerification verifyServerSignature(
            String base64Payload, String hmacKey) throws Exception {
        var json = asObject(parseBase64Json(base64Payload), "payload");
        return verifyServerSignature(new ServerSignaturePayload(
                stringField(json, "algorithm"),
                stringField(json, "apiKey"),
                stringField(json, "id"),
                stringField(json, "verificationData"),
                stringField(json, "signature"),
                Boolean.TRUE.equals(json.get("verified"))), hmacKey);
    }

    private static String stringField(Map<String, Object> json, String key) {
        return json.get(key) instanceof String s ? s : null;
    }

    /**
     * Parses Sentinel verification data like JS {@code parseVerificationData}: entries as
     * {@code URLSearchParams} reads them (a duplicate key keeps its first position and last
     * value), values typed as described in {@link ServerSignatureVerificationData}.
     */
    static ServerSignatureVerificationData parseVerificationData(String data) {
        var values = new LinkedHashMap<String, Object>();
        var start  = data.startsWith("?") ? 1 : 0;
        while (start <= data.length()) {
            var end = data.indexOf('&', start);
            if (end < 0) end = data.length();
            if (end > start) {
                var eq    = data.indexOf('=', start);
                var hasEq = eq >= 0 && eq < end;
                var name  = formDecode(data, start, hasEq ? eq : end);
                values.put(name, verificationValue(name, hasEq ? formDecode(data, eq + 1, end) : ""));
            }
            start = end + 1;
        }
        var ordered = new LinkedHashMap<String, Object>();
        for (var e : jsPropertyOrder(values, false)) ordered.put(e.getKey(), e.getValue());
        return new ServerSignatureVerificationData(Collections.unmodifiableMap(ordered));
    }

    private static Object verificationValue(String name, String value) {
        if (value.equals("true"))  return Boolean.TRUE;
        if (value.equals("false")) return Boolean.FALSE;
        if (isDigits(value, 0, value.length())) {
            return value.length() <= 15 ? (Object) Long.parseLong(value) : (Object) Double.parseDouble(value);
        }
        var dot = value.indexOf('.');
        if (dot > 0 && isDigits(value, 0, dot) && isDigits(value, dot + 1, value.length())) {
            return Double.parseDouble(value);
        }
        var trimmed = jsTrim(value);
        if ((name.equals("fields") || name.equals("reasons")) && !value.isEmpty()) {
            return List.of(trimmed.split(",", -1));
        }
        return trimmed;
    }

    /** {@code true} if {@code s[from, to)} is non-empty and all ASCII digits (JS regex {@code \d+}). */
    private static boolean isDigits(String s, int from, int to) {
        if (from >= to) return false;
        for (var i = from; i < to; i++) {
            var c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    /**
     * application/x-www-form-urlencoded decoding of {@code s[from, to)} like {@code URLSearchParams}:
     * {@code +} → space, valid {@code %XX} → byte, anything else kept; then
     * {@link #decodeUtf8 WHATWG UTF-8 decode}.
     */
    private static String formDecode(String s, int from, int to) {
        var in = utf8(s.substring(from, to));
        var out = new byte[in.length];
        var n = 0;
        for (var i = 0; i < in.length; i++) {
            var b = in[i];
            int hi, lo;
            if (b == '+') {
                out[n++] = ' ';
            } else if (b == '%' && i + 2 < in.length
                    && (hi = Character.digit(in[i + 1], 16)) >= 0 && (lo = Character.digit(in[i + 2], 16)) >= 0) {
                out[n++] = (byte) (hi << 4 | lo);
                i += 2;
            } else {
                out[n++] = b;
            }
        }
        return decodeUtf8(out, n);
    }

    /**
     * WHATWG "UTF-8 decode": one U+FFFD per maximal invalid subsequence (Java's decoder may
     * emit fewer, e.g. one for an encoded surrogate {@code ED A0 80}, where WHATWG emits three).
     */
    private static String decodeUtf8(byte[] bytes, int length) {
        var sb = new StringBuilder(length);
        int codePoint = 0, needed = 0, seen = 0, lower = 0x80, upper = 0xBF;
        for (var i = 0; i < length; i++) {
            var b = bytes[i] & 0xFF;
            if (needed == 0) {
                if (b <= 0x7F) {
                    sb.append((char) b);
                } else if (b >= 0xC2 && b <= 0xDF) {
                    needed = 1; codePoint = b & 0x1F;
                } else if (b >= 0xE0 && b <= 0xEF) {
                    if (b == 0xE0) lower = 0xA0;
                    if (b == 0xED) upper = 0x9F;
                    needed = 2; codePoint = b & 0x0F;
                } else if (b >= 0xF0 && b <= 0xF4) {
                    if (b == 0xF0) lower = 0x90;
                    if (b == 0xF4) upper = 0x8F;
                    needed = 3; codePoint = b & 0x07;
                } else {
                    sb.append('\uFFFD');
                }
                continue;
            }
            if (b < lower || b > upper) {
                codePoint = needed = seen = 0; lower = 0x80; upper = 0xBF;
                sb.append('\uFFFD');
                i--;  // reprocess this byte as a new sequence start
                continue;
            }
            lower = 0x80; upper = 0xBF;
            codePoint = codePoint << 6 | (b & 0x3F);
            if (++seen == needed) {
                sb.appendCodePoint(codePoint);
                codePoint = needed = seen = 0;
            }
        }
        if (needed != 0) sb.append('\uFFFD');
        return sb.toString();
    }

    /** UTF-8 bytes like JS {@code TextEncoder}: lone surrogates become U+FFFD (Java would write {@code ?}). */
    private static byte[] utf8(String s) {
        StringBuilder sb = null;
        for (var i = 0; i < s.length(); i++) {
            var c    = s.charAt(i);
            var pair = Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1));
            if (!pair && Character.isSurrogate(c)) {
                if (sb == null) sb = new StringBuilder(s.length()).append(s, 0, i);
                sb.append('\uFFFD');
            } else {
                if (sb != null) sb.append(c);
                if (pair) {
                    if (sb != null) sb.append(s.charAt(i + 1));
                    i++;
                }
            }
        }
        return (sb == null ? s : sb.toString()).getBytes(StandardCharsets.UTF_8);
    }

    /** JS {@code String.prototype.trim}. */
    private static String jsTrim(String s) {
        int from = 0, to = s.length();
        while (from < to && isJsWhitespace(s.charAt(from))) from++;
        while (to > from && isJsWhitespace(s.charAt(to - 1))) to--;
        return s.substring(from, to);
    }

    /** ECMAScript WhiteSpace or LineTerminator. */
    private static boolean isJsWhitespace(char c) {
        return c == '\t' || c == '\n' || c == 0x0B || c == '\f' || c == '\r' || c == '\uFEFF'
                || c == '\u2028' || c == '\u2029' || Character.getType(c) == Character.SPACE_SEPARATOR;
    }

    /** JS truthiness of a parsed verification value. */
    private static boolean jsTruthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean b) return b;
        if (v instanceof Number n) return n.doubleValue() != 0 && !Double.isNaN(n.doubleValue());
        if (v instanceof String s) return !s.isEmpty();
        return true;
    }

    /** JS {@code ToNumber} of a parsed verification value (Boolean, Number or String). */
    private static double jsToNumber(Object v) {
        if (v instanceof Number n)  return n.doubleValue();
        if (v instanceof Boolean b) return b ? 1 : 0;
        if (v instanceof String s)  return jsStringToNumber(s);
        return Double.NaN;
    }

    // Possessive quantifiers: the input is attacker-controlled (Sentinel `expire`), and a backtracking
    // `\d+\.?\d*` makes matches() quadratic on long digit runs.
    private static final Pattern JS_DECIMAL_LITERAL =
            Pattern.compile("[+-]?+(?:Infinity|(?:\\d++(?:\\.\\d*+)?|\\.\\d++)(?:[eE][+-]?+\\d++)?)");
    private static final Pattern JS_NON_DECIMAL_LITERAL =
            Pattern.compile("0(?:[xX][0-9a-fA-F]++|[oO][0-7]++|[bB][01]++)");

    /** JS {@code StringToNumber}. */
    private static double jsStringToNumber(String s) {
        var t = jsTrim(s);
        if (t.isEmpty()) return 0;
        if (JS_DECIMAL_LITERAL.matcher(t).matches()) {
            if (!t.endsWith("Infinity")) return Double.parseDouble(t);
            return t.startsWith("-") ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
        }
        if (JS_NON_DECIMAL_LITERAL.matcher(t).matches()) {
            var radix = switch (Character.toLowerCase(t.charAt(1))) { case 'x' -> 16; case 'o' -> 8; default -> 2; };
            var bitsPerDigit = Integer.numberOfTrailingZeros(radix);
            var first = 2;
            while (first < t.length() && t.charAt(first) == '0') first++;
            if (first == t.length()) return 0;
            // value >= radix^(digits-1) >= 2^1024 rounds to Infinity; bounding the digits keeps
            // BigInteger parsing (quadratic) to at most ~1024 bits.
            if ((long) (t.length() - first - 1) * bitsPerDigit >= 1024) return Double.POSITIVE_INFINITY;
            return new BigInteger(t.substring(first), radix).doubleValue();
        }
        return Double.NaN;
    }

    // -------------------------------------------------------------------------
    // Canonical JSON
    // -------------------------------------------------------------------------

    /**
     * Produces the canonical JSON representation of {@link ChallengeParameters}.
     *
     * <p>Matches JS {@code JSON.stringify(sortKeys(parameters))}: keys sorted
     * lexicographically, numbers formatted as in JS. Null fields are omitted.
     * This format is used for HMAC signing.</p>
     */
    static String canonicalJson(ChallengeParameters p) {
        var fields = new TreeMap<String, Object>();
        fields.put("algorithm",  p.algorithm());
        fields.put("cost",       p.cost());
        if (p.data()         != null) fields.put("data",         p.data());
        if (p.expiresAt()    != null) fields.put("expiresAt",    p.expiresAt());
        fields.put("keyLength",  p.keyLength());
        fields.put("keyPrefix",  p.keyPrefix());
        if (p.keySignature() != null) fields.put("keySignature", p.keySignature());
        if (p.memoryCost()   != null) fields.put("memoryCost",   p.memoryCost());
        fields.put("nonce",      p.nonce());
        if (p.parallelism()  != null) fields.put("parallelism",  p.parallelism());
        fields.put("salt",       p.salt());
        return encodeValue(fields);
    }

    /**
     * Encodes a value as canonical JSON, identical to JS {@code JSON.stringify(sortKeys(value))}:
     * object keys are sorted recursively except inside arrays (which {@code sortKeys} does not
     * descend into), objects are emitted in JS property order, and numbers and strings use
     * {@code JSON.stringify} formatting.
     */
    private static String encodeValue(Object value) {
        var sb = new StringBuilder();
        encodeValue(sb, value, true);
        return sb.toString();
    }

    private static void encodeValue(StringBuilder sb, Object value, boolean sortKeys) {
        if (value == null || JSONObject.NULL.equals(value)) { sb.append("null"); return; }
        if (value instanceof String s)  { appendJsonString(sb, s); return; }
        if (value instanceof Number n)  { sb.append(jsNumber(n)); return; }
        if (value instanceof Boolean b) { sb.append(b.booleanValue()); return; }
        if (value instanceof JSONObject o) { encodeValue(sb, o.toMap(), sortKeys); return; }
        if (value instanceof JSONArray a)  { encodeValue(sb, a.toList(), sortKeys); return; }
        if (value instanceof Map<?, ?> m) {
            sb.append('{');
            var first = true;
            for (var entry : jsPropertyOrder(m, sortKeys)) {
                if (!first) sb.append(',');
                first = false;
                appendJsonString(sb, entry.getKey());
                sb.append(':');
                encodeValue(sb, entry.getValue(), sortKeys);
            }
            sb.append('}');
            return;
        }
        if (value instanceof Iterable<?> it) {
            sb.append('[');
            var first = true;
            for (var item : it) {
                if (!first) sb.append(',');
                first = false;
                encodeValue(sb, item, false);
            }
            sb.append(']');
            return;
        }
        if (value instanceof Object[] arr) { encodeValue(sb, Arrays.asList(arr), sortKeys); return; }
        throw new IllegalArgumentException("Unsupported JSON value type: " + value.getClass().getName());
    }

    /**
     * Orders map entries as a JS object built from them would enumerate: array-index keys
     * ({@code "0"}..{@code "4294967294"}) first in ascending numeric order, then the remaining
     * keys sorted (if {@code sortKeys}, by UTF-16 code units like {@code Array.prototype.sort})
     * or in the map's iteration order.
     */
    private static List<Map.Entry<String, Object>> jsPropertyOrder(Map<?, ?> map, boolean sortKeys) {
        var entries = new ArrayList<Map.Entry<String, Object>>(map.size());
        for (var e : map.entrySet()) {
            entries.add(new AbstractMap.SimpleImmutableEntry<>(String.valueOf(e.getKey()), e.getValue()));
        }
        if (sortKeys) entries.sort(Map.Entry.comparingByKey());
        // Stable sort: moves array-index keys to the front, keeps the order of the rest.
        entries.sort((a, b) -> {
            var ia = arrayIndex(a.getKey());
            var ib = arrayIndex(b.getKey());
            if (ia < 0) return ib < 0 ? 0 : 1;
            return ib < 0 ? -1 : Long.compare(ia, ib);
        });
        return entries;
    }

    /** Returns the numeric value if {@code key} is a JS array index (canonical uint32 below 2^32 - 1), else -1. */
    private static long arrayIndex(String key) {
        var len = key.length();
        if (len == 0 || len > 10 || (len > 1 && key.charAt(0) == '0')) return -1;
        var value = 0L;
        for (var i = 0; i < len; i++) {
            var c = key.charAt(i);
            if (c < '0' || c > '9') return -1;
            value = value * 10 + (c - '0');
        }
        return value <= 0xFFFF_FFFEL ? value : -1;
    }

    private static final long MAX_SAFE_INTEGER = (1L << 53) - 1;

    /**
     * Formats a number like JS {@code JSON.stringify}. JS numbers are doubles, so every
     * value is formatted as its nearest double; non-finite values become {@code null}.
     */
    static String jsNumber(Number n) {
        if (n instanceof Integer || n instanceof Short || n instanceof Byte) return n.toString();
        if (n instanceof Long l && l >= -MAX_SAFE_INTEGER && l <= MAX_SAFE_INTEGER) return l.toString();
        return jsNumber(n.doubleValue());
    }

    /** ECMAScript {@code Number::toString(x)} (radix 10), with {@code null} for NaN/Infinity as in JSON. */
    static String jsNumber(double d) {
        if (!Double.isFinite(d)) return "null";
        if (d == 0) return "0"; // also -0
        if (d < 0) return "-" + jsNumber(-d);
        if (d <= MAX_SAFE_INTEGER && d == Math.rint(d)) return Long.toString((long) d);

        // Shortest digits k and exponent n with d = 0.digits × 10^n
        var shortest = shortestDecimal(d);
        var digits   = shortest.unscaledValue().toString();
        var k        = digits.length();
        var e        = k - shortest.scale();

        if (k <= e && e <= 21) return digits + "0".repeat(e - k);
        if (0 < e && e <= 21)  return digits.substring(0, e) + "." + digits.substring(e);
        if (-6 < e && e <= 0)  return "0." + "0".repeat(-e) + digits;
        var exp      = e - 1;
        var mantissa = k == 1 ? digits : digits.charAt(0) + "." + digits.substring(1);
        return mantissa + "e" + (exp < 0 ? "-" : "+") + Math.abs(exp);
    }

    /**
     * Shortest decimal that rounds to {@code d} (positive, finite); among equally short
     * candidates the one closest to {@code d}. Not using {@code Double.toString}: before
     * JDK 19 it does not always return the shortest representation (JDK-4511638).
     */
    private static BigDecimal shortestDecimal(double d) {
        var exact = new BigDecimal(d);
        for (var precision = 1; ; precision++) {
            var nearest = exact.round(new MathContext(precision, RoundingMode.HALF_EVEN));
            if (nearest.doubleValue() == d) return nearest.stripTrailingZeros();
            // At powers of two the rounding interval is asymmetric: the farther neighbour may still round-trip.
            for (var mode : new RoundingMode[]{RoundingMode.FLOOR, RoundingMode.CEILING}) {
                var candidate = exact.round(new MathContext(precision, mode));
                if (candidate.doubleValue() == d) return candidate.stripTrailingZeros();
            }
        }
    }

    private static void appendJsonString(StringBuilder sb, String s) {
        sb.append('"');
        for (var i = 0; i < s.length(); i++) {
            var c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> {
                    if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                        sb.append(c).append(s.charAt(++i));
                    } else if (c < 0x20 || Character.isSurrogate(c)) {
                        // Control characters and lone surrogates (well-formed JSON.stringify)
                        sb.append("\\u").append(HEX_DIGITS[c >> 12]).append(HEX_DIGITS[(c >> 8) & 0xf])
                          .append(HEX_DIGITS[(c >> 4) & 0xf]).append(HEX_DIGITS[c & 0xf]);
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    // -------------------------------------------------------------------------
    // PBKDF2 – manual implementation for raw-byte compatibility with Node.js
    // -------------------------------------------------------------------------

    /**
     * PBKDF2 implementation using HMAC with raw byte password material.
     *
     * <p>Java's {@code SecretKeyFactory("PBKDF2With...")} converts {@code char[]}
     * passwords to bytes via UTF-16BE, which differs from Node.js / Web Crypto
     * that use raw bytes directly. This implementation uses {@code Mac} with
     * {@code SecretKeySpec(password, ...)} to pass bytes through unchanged,
     * ensuring cross-platform compatibility.</p>
     */
    static byte[] pbkdf2Hmac(String hmacName, byte[] password, byte[] salt,
            int iterations, int keyLength) throws Exception {
        var mac = Mac.getInstance(hmacName);
        mac.init(new SecretKeySpec(password, hmacName));
        var hashLen = mac.getMacLength();
        var blocks  = (int) Math.ceil((double) keyLength / hashLen);
        var dk      = new byte[keyLength];

        for (var block = 1; block <= blocks; block++) {
            // PRF(password, salt || INT(block))
            var input = new byte[salt.length + 4];
            System.arraycopy(salt, 0, input, 0, salt.length);
            input[salt.length]     = (byte) (block >>> 24);
            input[salt.length + 1] = (byte) (block >>> 16);
            input[salt.length + 2] = (byte) (block >>> 8);
            input[salt.length + 3] = (byte)  block;

            mac.reset();
            var u = mac.doFinal(input);
            var f = u.clone();

            for (var i = 1; i < iterations; i++) {
                mac.reset();
                u = mac.doFinal(u);
                for (var j = 0; j < f.length; j++) f[j] ^= u[j];
            }

            var offset = (block - 1) * hashLen;
            var len    = Math.min(hashLen, keyLength - offset);
            System.arraycopy(f, 0, dk, offset, len);
        }
        return dk;
    }

    // -------------------------------------------------------------------------
    // Private utilities
    // -------------------------------------------------------------------------

    public static byte[] randomBytes(int length) {
        var bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * WebCrypto hash name: {@code SHA-1}, {@code SHA-256}, {@code SHA-384} or {@code SHA-512}
     * (case-insensitive); any other name throws, as in JS.
     */
    private static String webCryptoHash(String algorithm) {
        var name = algorithm == null ? "" : algorithm.toUpperCase(Locale.ROOT);
        return switch (name) {
            case "SHA-1", "SHA-256", "SHA-384", "SHA-512" -> name;
            default -> throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm);
        };
    }

    /** HMAC as WebCrypto does it; the algorithm is a {@link #webCryptoHash WebCrypto hash name}. */
    static String hmacHex(String algorithm, byte[] data, String key) throws Exception {
        var hmacName = "Hmac" + webCryptoHash(algorithm).replace("-", "");
        var mac = Mac.getInstance(hmacName);
        mac.init(new SecretKeySpec(utf8(key), hmacName));
        return bytesToHex(mac.doFinal(data));
    }

    static boolean constantTimeEqual(String a, String b) {
        if (a.length() != b.length()) return false;
        var result = 0;
        for (var i = 0; i < a.length(); i++) result |= a.charAt(i) ^ b.charAt(i);
        return result == 0;
    }

    /**
     * Decodes an even-length key prefix to bytes (so hex case does not matter); returns
     * {@code null} for an odd-length prefix, which is matched as lowercase hex. Same as JS.
     */
    private static byte[] keyPrefixBytes(String keyPrefix) {
        return keyPrefix.length() % 2 == 0 ? hexToBytes(keyPrefix) : null;
    }

    /** JS key-prefix check; {@code keyPrefixBuf} is {@link #keyPrefixBytes(String) keyPrefixBytes(keyPrefix)}. */
    private static boolean keyPrefixMatches(byte[] derivedKey, String keyPrefix, byte[] keyPrefixBuf) {
        return keyPrefixBuf != null ? startsWith(derivedKey, keyPrefixBuf) : hexStartsWith(derivedKey, keyPrefix);
    }

    /**
     * JS {@code bytes.slice(0, end)}: truncates to the available bytes (never pads);
     * a negative {@code end} counts from the end.
     */
    static byte[] jsSlice(byte[] bytes, int end) {
        var length = end < 0 ? Math.max(bytes.length + end, 0) : Math.min(end, bytes.length);
        return length == bytes.length ? bytes : Arrays.copyOf(bytes, length);
    }

    static boolean startsWith(byte[] buffer, byte[] prefix) {
        if (prefix.length > buffer.length) return false;
        for (var i = 0; i < prefix.length; i++) {
            if (buffer[i] != prefix[i]) return false;
        }
        return true;
    }

    static byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0) throw new IllegalArgumentException("Hex string must have even length: " + hex);
        return HexFormat.of().parseHex(hex);
    }

    /** JS truthiness for optional strings: {@code null} and {@code ""} both mean unset. */
    private static boolean isSet(String s) {
        return s != null && !s.isEmpty();
    }

    /** Returns {@code true} if {@code s} is non-null, even-length and contains only ASCII hex digits. */
    static boolean isHex(String s) {
        if (s == null || s.length() % 2 != 0) return false;
        for (var i = 0; i < s.length(); i++) {
            if (!HexFormat.isHexDigit(s.charAt(i))) return false;
        }
        return true;
    }

    /** Equivalent to {@code bytesToHex(buffer).startsWith(hexPrefix)} without allocating. */
    static boolean hexStartsWith(byte[] buffer, String hexPrefix) {
        if (hexPrefix.length() > buffer.length * 2) return false;
        for (var i = 0; i < hexPrefix.length(); i++) {
            var b      = buffer[i >> 1];
            var nibble = (i & 1) == 0 ? (b >> 4) & 0x0f : b & 0x0f;
            if (hexPrefix.charAt(i) != Character.forDigit(nibble, 16)) return false;
        }
        return true;
    }

    public static String bytesToHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    /** Elapsed ms since {@code t0}, floored to 1 decimal like JS {@code timeDuration}. */
    private static double elapsed(long t0) {
        return ((System.nanoTime() - t0) / 100_000) / 10.0;
    }

    /** Decodes base64 and parses the JSON document with {@link #parseOrdered}; trailing content is an error. */
    private static Object parseBase64Json(String base64Payload) {
        var x = new JSONTokener(new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8));
        var value = parseOrdered(x);
        if (x.nextClean() != 0) throw x.syntaxError("Unexpected trailing content");
        return value;
    }

    /**
     * Parses a JSON value like JS {@code JSON.parse}: objects become insertion-ordered maps
     * (a duplicate key keeps its first position and its last value), arrays become lists,
     * {@code null} becomes Java {@code null}. Scalars are parsed here rather than by org.json,
     * whose BigInteger/BigDecimal number parsing is quadratic in the digit count (the input is
     * unauthenticated).
     */
    private static Object parseOrdered(JSONTokener x) {
        var c = x.nextClean();
        if (c == '{') {
            var map = new LinkedHashMap<String, Object>();
            if (x.nextClean() == '}') return map;
            x.back();
            while (true) {
                if (x.nextClean() != '"') throw x.syntaxError("Expected a string key");
                var key = x.nextString('"');
                if (x.nextClean() != ':') throw x.syntaxError("Expected ':' after key");
                map.put(key, parseOrdered(x));
                c = x.nextClean();
                if (c == '}') return map;
                if (c != ',') throw x.syntaxError("Expected ',' or '}'");
            }
        }
        if (c == '[') {
            var list = new ArrayList<Object>();
            if (x.nextClean() == ']') return list;
            x.back();
            while (true) {
                list.add(parseOrdered(x));
                c = x.nextClean();
                if (c == ']') return list;
                if (c != ',') throw x.syntaxError("Expected ',' or ']'");
            }
        }
        if (c == '"') return x.nextString('"');
        var token = new StringBuilder();
        for (; c != 0 && ",:]} \t\n\r".indexOf(c) < 0; c = x.next()) token.append(c);
        if (c != 0) x.back();
        return jsonScalar(token.toString(), x);
    }

    private static final Pattern JSON_NUMBER =
            Pattern.compile("-?+(?:0|[1-9]\\d*+)(\\.\\d++)?+([eE][+-]?+\\d++)?+");

    /**
     * A JSON literal or number. Integer literals keep org.json's types ({@code Integer}, else
     * {@code Long}); anything else becomes the nearest {@code Double}, as in JS.
     */
    private static Object jsonScalar(String token, JSONTokener x) {
        switch (token) {
            case "true":  return Boolean.TRUE;
            case "false": return Boolean.FALSE;
            case "null":  return null;
            default:      break;
        }
        var m = JSON_NUMBER.matcher(token);
        if (!m.matches()) {
            throw x.syntaxError("Unexpected token '" + token.substring(0, Math.min(token.length(), 32)) + "'");
        }
        if (m.group(1) == null && m.group(2) == null && token.length() <= 20) {
            try {
                var l = Long.parseLong(token);
                if (l == (int) l) return (int) l;
                return l;
            } catch (NumberFormatException beyondLong) {
                // falls through to the nearest double
            }
        }
        return Double.parseDouble(token);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object value, String name) {
        if (!(value instanceof Map<?, ?>)) throw new JSONException("\"" + name + "\" is not a JSON object");
        return (Map<String, Object>) value;
    }

    /** A required string field, like org.json {@code getString}. */
    private static String requiredString(Map<String, Object> map, String key) {
        if (map.get(key) instanceof String s) return s;
        throw new JSONException("\"" + key + "\" is not a string");
    }

    /** An optional field as a string, like org.json {@code optString(key, null)}. */
    private static String optionalString(Map<String, Object> map, String key) {
        var value = map.get(key);
        return value == null ? null : value.toString();
    }

    /** A required numeric field, like org.json {@code getInt}/{@code getLong}/{@code getDouble}: a number or a numeric string. */
    private static <T> T requiredNumber(Map<String, Object> map, String key,
            Function<String, T> parse, Function<Number, T> convert) {
        var value = map.get(key);
        if (value instanceof Number n) return convert.apply(n);
        if (value == null) throw new JSONException("\"" + key + "\" not found");
        try {
            return parse.apply(value.toString());
        } catch (NumberFormatException e) {
            throw new JSONException("\"" + key + "\" is not a number", e);
        }
    }

    /** A parsed JSON number as JS holds it: {@code Long} for integer literals, otherwise the nearest {@code Double}. */
    private static Number jsonNumber(Object value, String name) {
        if (value instanceof Integer || value instanceof Long) return ((Number) value).longValue();
        if (value instanceof Number n) return n.doubleValue();
        throw new JSONException("\"" + name + "\" is not a number");
    }
}
