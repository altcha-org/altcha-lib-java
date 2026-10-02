package org.altcha.altcha.v2;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;
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
            Long expiresAt,        // nullable – unix timestamp (seconds)
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

    /** The solution found by brute-forcing counter values. */
    public record Solution(int counter, String derivedKey, Long time) {}

    /** Full v2 payload sent from the client after solving. */
    public record Payload(Challenge challenge, Solution solution) {}

    /** Structured result returned by {@link #verifySolution}. */
    public record VerifySolutionResult(
            boolean verified,
            boolean expired,
            Boolean invalidSignature,  // null when expired before checking
            Boolean invalidSolution,   // null when signature was invalid
            long time) {

        /** Serialises this result to a JSON object string. */
        public String toJson() {
            var sb = new StringBuilder("{");
            sb.append("\"expired\":").append(expired).append(',');
            if (invalidSignature != null) sb.append("\"invalidSignature\":").append(invalidSignature).append(',');
            if (invalidSolution  != null) sb.append("\"invalidSolution\":").append(invalidSolution).append(',');
            sb.append("\"time\":").append(time).append(',');
            sb.append("\"verified\":").append(verified);
            return sb.append('}').toString();
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

    /** Result of verifying a server-attestation payload. */
    public record ServerSignatureVerification(
            boolean verified,
            ServerSignatureVerificationData verificationData) {

        /** Serialises this result to a JSON object string. */
        public String toJson() {
            var sb = new StringBuilder("{");
            sb.append("\"verified\":").append(verified);
            if (verificationData != null) sb.append(",\"verificationData\":").append(verificationData.toJson());
            return sb.append('}').toString();
        }
    }

    /** Parsed verification data from the ALTCHA Sentinel service. */
    public record ServerSignatureVerificationData(
            String classification,
            String email,
            Long expire,
            String[] fields,
            String fieldsHash,
            String ipAddress,
            String[] reasons,
            double score,
            long time,
            boolean verified,
            Map<String, String> additionalFields) {

        public String getAdditionalField(String name) {
            return additionalFields.get(name);
        }

        public boolean hasAdditionalField(String name) {
            return additionalFields.containsKey(name);
        }

        /** Serialises this verification data to a JSON object string. */
        public String toJson() {
            var sb = new StringBuilder("{");
            var first = true;
            if (classification != null) { sb.append("\"classification\":").append(jsonString(classification)); first = false; }
            if (email          != null) { if (!first) sb.append(','); sb.append("\"email\":").append(jsonString(email)); first = false; }
            if (expire         != null) { if (!first) sb.append(','); sb.append("\"expire\":").append(expire); first = false; }
            if (fields         != null) {
                if (!first) sb.append(',');
                sb.append("\"fields\":[");
                for (var i = 0; i < fields.length; i++) { if (i > 0) sb.append(','); sb.append(jsonString(fields[i])); }
                sb.append(']');
                first = false;
            }
            if (fieldsHash  != null) { if (!first) sb.append(','); sb.append("\"fieldsHash\":").append(jsonString(fieldsHash)); first = false; }
            if (ipAddress   != null) { if (!first) sb.append(','); sb.append("\"ipAddress\":").append(jsonString(ipAddress)); first = false; }
            if (reasons     != null) {
                if (!first) sb.append(',');
                sb.append("\"reasons\":[");
                for (var i = 0; i < reasons.length; i++) { if (i > 0) sb.append(','); sb.append(jsonString(reasons[i])); }
                sb.append(']');
                first = false;
            }
            if (!first) sb.append(',');
            sb.append("\"score\":").append(score).append(',');
            sb.append("\"time\":").append(time).append(',');
            sb.append("\"verified\":").append(verified);
            if (additionalFields != null) {
                for (var entry : new TreeMap<>(additionalFields).entrySet()) {
                    sb.append(',').append(jsonString(entry.getKey())).append(':').append(jsonString(entry.getValue()));
                }
            }
            return sb.append('}').toString();
        }
    }

    // -------------------------------------------------------------------------
    // Key derivation interface
    // -------------------------------------------------------------------------

    /** Result returned by a {@link KeyDerivationFunction}. */
    public record DeriveKeyResult(byte[] derivedKey) {}

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
     * Manages the password buffer passed to the KDF for each counter iteration.
     *
     * <p>The counter is appended to the nonce as a big-endian 32-bit unsigned integer.
     * The returned array from {@link #setCounter} is a view of an internal buffer –
     * do not retain a reference across iterations.</p>
     */
    public static final class PasswordBuffer {
        private final byte[] nonce;
        private final byte[] buffer;

        public PasswordBuffer(byte[] nonce) {
            this.nonce  = nonce;
            this.buffer = new byte[nonce.length + 4];
            System.arraycopy(nonce, 0, buffer, 0, nonce.length);
        }

        /** Updates the counter bytes in-place and returns the combined nonce+counter buffer. */
        public byte[] setCounter(int n) {
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
        public Integer counter;
        public int cost;
        public Map<String, Object> data;
        public KeyDerivationFunction deriveKey;
        public Long expiresAt;
        public String hmacAlgorithm = DEFAULT_HMAC_ALGORITHM;
        public String hmacKeySignatureSecret;
        public String hmacSignatureSecret;
        public int keyLength = DEFAULT_KEY_LENGTH;
        public String keyPrefix = DEFAULT_KEY_PREFIX;
        public Integer keyPrefixLength;
        public Integer memoryCost;
        public Integer parallelism;

        public CreateChallengeOptions algorithm(String v)                  { algorithm = v; return this; }
        public CreateChallengeOptions counter(Integer v)                   { counter = v; return this; }
        public CreateChallengeOptions cost(int v)                          { cost = v; return this; }
        public CreateChallengeOptions data(Map<String, Object> v)          { data = v; return this; }
        public CreateChallengeOptions deriveKey(KeyDerivationFunction v)   { deriveKey = v; return this; }
        public CreateChallengeOptions expiresAt(Long v)                    { expiresAt = v; return this; }
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
            return new DeriveKeyResult(Arrays.copyOf(derived, params.keyLength()));
        };
    }

    // -------------------------------------------------------------------------
    // Challenge creation
    // -------------------------------------------------------------------------

    /**
     * Creates a new v2 proof-of-work challenge.
     *
     * <p>If {@link CreateChallengeOptions#counter} is set, the KDF is invoked once
     * and the first {@code keyPrefixLength} bytes of the derived key become the
     * {@code keyPrefix} (deterministic mode). Otherwise a static prefix (default
     * {@code "00"}) is used and the client must brute-force the counter.</p>
     *
     * <p>If {@link CreateChallengeOptions#hmacSignatureSecret} is set, the
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
            var pw       = new PasswordBuffer(nonceBuf);
            var result   = kdfFn.deriveKey(params, saltBuf, pw.setCounter(options.counter));
            derivedKey   = result.derivedKey();
            params       = params.withKeyPrefix(bytesToHex(Arrays.copyOf(derivedKey, prefixLength)));
        }

        if (options.hmacSignatureSecret == null) {
            return new Challenge(params, null);
        }

        return signChallenge(options.hmacAlgorithm, params, derivedKey,
                options.hmacSignatureSecret, options.hmacKeySignatureSecret);
    }

    /** Signs challenge parameters with HMAC. Optionally also signs the derived key. */
    public static Challenge signChallenge(String hmacAlgorithm, ChallengeParameters params,
            byte[] derivedKey, String hmacSignatureSecret, String hmacKeySignatureSecret)
            throws Exception {
        if (derivedKey != null && hmacKeySignatureSecret != null) {
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
     * @param challenge    the challenge to solve
     * @param kdfFn        the KDF to use (must match the algorithm in the challenge)
     * @param counterStart starting counter value (0 for a fresh solve)
     * @param counterStep  increment between attempts (1 for single-threaded)
     */
    public static Solution solveChallenge(Challenge challenge, KeyDerivationFunction kdfFn,
            int counterStart, int counterStep) throws Exception {
        var params        = challenge.parameters();
        var nonceBuf      = hexToBytes(params.nonce());
        var saltBuf       = hexToBytes(params.salt());
        var keyPrefix     = params.keyPrefix();
        // Even-length prefix: byte compare. Odd-length: lowercase hex string prefix match (as in the JS reference).
        var keyPrefixBuf  = keyPrefix.length() % 2 == 0 ? hexToBytes(keyPrefix) : null;
        var pw            = new PasswordBuffer(nonceBuf);
        var t0            = System.nanoTime();
        var counter       = counterStart;

        while (true) {
            var derivedKey = kdfFn.deriveKey(params, saltBuf, pw.setCounter(counter)).derivedKey();
            if (keyPrefixBuf != null ? startsWith(derivedKey, keyPrefixBuf) : hexStartsWith(derivedKey, keyPrefix)) {
                return new Solution(counter, bytesToHex(derivedKey),
                        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0));
            }
            counter += counterStep;
        }
    }

    /** Convenience overload: starts at counter 0, step 1. */
    public static Solution solveChallenge(Challenge challenge, KeyDerivationFunction kdfFn)
            throws Exception {
        return solveChallenge(challenge, kdfFn, 0, 1);
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
     * @param hmacAlgorithm           HMAC algorithm used when the challenge was signed
     *                                ({@code "SHA-256"}, {@code "SHA-384"} or {@code "SHA-512"});
     *                                {@code null} means {@link #DEFAULT_HMAC_ALGORITHM}
     * @param kdfFn                   KDF to use when re-deriving (may be {@code null} if
     *                                {@code keySignature} is present)
     */
    public static VerifySolutionResult verifySolution(
            Challenge challenge,
            Solution solution,
            String hmacSignatureSecret,
            String hmacKeySignatureSecret,
            String hmacAlgorithm,
            KeyDerivationFunction kdfFn) throws Exception {

        if (hmacSignatureSecret == null || hmacSignatureSecret.isBlank()) {
            throw new IllegalArgumentException("hmacSignatureSecret is required for v2 verification");
        }

        var t0     = System.nanoTime();
        var params = challenge.parameters();

        // 1. Expiry (against fractional seconds, like JS `expiresAt < Date.now() / 1000`)
        if (params.expiresAt() != null && params.expiresAt() < System.currentTimeMillis() / 1000.0) {
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
        if (params.keySignature() != null && hmacKeySignatureSecret != null) {
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
        var pw       = new PasswordBuffer(nonceBuf);
        var result   = kdfFn.deriveKey(params, saltBuf, pw.setCounter(solution.counter()));
        var rederived = bytesToHex(result.derivedKey());
        var keyMatches    = constantTimeEqual(rederived, solution.derivedKey());
        var prefixMatches = rederived.startsWith(params.keyPrefix());
        var valid         = keyMatches && prefixMatches;
        return new VerifySolutionResult(valid, false, false, !valid, elapsed(t0));
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
        var json = new JSONTokener(
                new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8));
        var root = parseOrdered(json);
        if (json.nextClean() != 0) throw json.syntaxError("Unexpected trailing content");
        var rootMap       = asObject(root, "payload");
        var challengeMap  = asObject(rootMap.get("challenge"), "challenge");
        var paramsMap     = asObject(challengeMap.get("parameters"), "parameters");
        var challengeObj  = new JSONObject(challengeMap);
        var paramsObj     = new JSONObject(paramsMap);
        var solutionObj   = new JSONObject(asObject(rootMap.get("solution"), "solution"));

        var params = new ChallengeParameters(
                paramsObj.getString("algorithm"),
                paramsObj.getString("nonce"),
                paramsObj.getString("salt"),
                paramsObj.getInt("cost"),
                paramsObj.getInt("keyLength"),
                paramsObj.getString("keyPrefix"),
                paramsObj.optString("keySignature", null),
                paramsObj.has("memoryCost") && !paramsObj.isNull("memoryCost") ? paramsObj.getInt("memoryCost") : null,
                paramsObj.has("parallelism") && !paramsObj.isNull("parallelism") ? paramsObj.getInt("parallelism") : null,
                paramsObj.has("expiresAt")   && !paramsObj.isNull("expiresAt")   ? paramsObj.getLong("expiresAt")  : null,
                paramsMap.get("data") != null ? asObject(paramsMap.get("data"), "data") : null);

        var challenge = new Challenge(params,
                challengeObj.optString("signature", null));
        var solution  = new Solution(
                solutionObj.getInt("counter"),
                solutionObj.getString("derivedKey"),
                solutionObj.has("time") && !solutionObj.isNull("time") ? solutionObj.getLong("time") : null);

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
            var json = new JSONObject(
                    new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8));
            return json.has("verificationData");
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
        var payload = parsePayload(base64Payload);
        return verifySolution(payload.challenge(), payload.solution(), hmacSignatureSecret, kdfFn);
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

    public static ServerSignatureVerification verifyServerSignature(
            ServerSignaturePayload payload, String hmacKey) throws Exception {
        if (payload.algorithm() == null || payload.verificationData() == null
                || payload.verificationData().isBlank() || payload.signature() == null) {
            return new ServerSignatureVerification(false, null);
        }
        return verifyServerSignatureInternal(payload, hmacKey);
    }

    public static ServerSignatureVerification verifyServerSignature(
            String base64Payload, String hmacKey) throws Exception {
        var json = new JSONObject(
                new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8));
        if (!json.has("algorithm") || !json.has("verificationData")
                || !json.has("signature") || !json.has("verified")) {
            return new ServerSignatureVerification(false, null);
        }
        var payload = new ServerSignaturePayload(
                json.getString("algorithm"),
                json.optString("apiKey", null),
                json.optString("id", null),
                json.getString("verificationData"),
                json.getString("signature"),
                json.getBoolean("verified"));
        return verifyServerSignatureInternal(payload, hmacKey);
    }

    private static ServerSignatureVerification verifyServerSignatureInternal(
            ServerSignaturePayload payload, String hmacKey) throws Exception {
        var digest      = MessageDigest.getInstance(payload.algorithm());
        var hash        = digest.digest(payload.verificationData().getBytes(StandardCharsets.UTF_8));
        var expectedSig = hmacHex(payload.algorithm(), hash, hmacKey);
        var verData     = extractVerificationData(payload.verificationData());
        var now         = System.currentTimeMillis() / 1000;
        var verified    = payload.verified()
                && verData.verified()
                && (verData.expire() == null || verData.expire() > now)
                && payload.signature().equals(expectedSig);
        return new ServerSignatureVerification(verified, verData);
    }

    private static ServerSignatureVerificationData extractVerificationData(String raw)
            throws Exception {
        var params = parseQueryParams(raw);
        var predefined = Set.of("classification", "email", "expire", "fields", "fieldsHash",
                "ipAddress", "reasons", "score", "time", "verified");
        var extra = new LinkedHashMap<String, String>();
        for (var e : params.entrySet()) {
            if (!predefined.contains(e.getKey())) extra.put(e.getKey(), e.getValue());
        }
        return new ServerSignatureVerificationData(
                params.get("classification"),
                params.get("email"),
                params.containsKey("expire") ? Long.parseLong(params.get("expire")) : null,
                params.containsKey("fields")  ? params.get("fields").split(",")  : null,
                params.get("fieldsHash"),
                params.get("ipAddress"),
                params.containsKey("reasons") ? params.get("reasons").split(",") : null,
                params.containsKey("score")   ? Double.parseDouble(params.get("score")) : 0.0,
                params.containsKey("time")    ? Long.parseLong(params.get("time")) : 0L,
                Boolean.parseBoolean(params.getOrDefault("verified", "false")),
                Collections.unmodifiableMap(extra));
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

    /** Returns a JSON-escaped quoted string, identical to JS {@code JSON.stringify}. */
    static String jsonString(String s) {
        var sb = new StringBuilder(s.length() + 2);
        appendJsonString(sb, s);
        return sb.toString();
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

    static String hmacHex(String algorithm, byte[] data, String key) throws Exception {
        var hmacName = switch (algorithm) {
            case "SHA-512" -> "HmacSHA512";
            case "SHA-384" -> "HmacSHA384";
            default        -> "HmacSHA256";
        };
        var mac = Mac.getInstance(hmacName);
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), hmacName));
        return bytesToHex(mac.doFinal(data));
    }

    static boolean constantTimeEqual(String a, String b) {
        if (a.length() != b.length()) return false;
        var result = 0;
        for (var i = 0; i < a.length(); i++) result |= a.charAt(i) ^ b.charAt(i);
        return result == 0;
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

    private static long elapsed(long t0) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
    }

    /**
     * Parses a JSON value like JS {@code JSON.parse}: objects become insertion-ordered maps
     * (a duplicate key keeps its first position and its last value), arrays become lists,
     * {@code null} becomes Java {@code null}. Strings and numbers are parsed by org.json.
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
        x.back();
        var value = x.nextValue();
        return JSONObject.NULL.equals(value) ? null : value;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object value, String name) {
        if (!(value instanceof Map<?, ?>)) throw new JSONException("\"" + name + "\" is not a JSON object");
        return (Map<String, Object>) value;
    }

    private static Map<String, String> parseQueryParams(String raw) throws Exception {
        var result   = new LinkedHashMap<String, String>();
        // Use the segment after the last '?' if present; otherwise parse the whole string.
        var parts    = raw.split("\\?");
        var paramStr = parts[parts.length - 1];
        for (var pair : paramStr.split("&")) {
            var kv = pair.split("=", 2);
            if (kv.length == 2) {
                result.put(java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                           java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
            }
        }
        return result;
    }
}
