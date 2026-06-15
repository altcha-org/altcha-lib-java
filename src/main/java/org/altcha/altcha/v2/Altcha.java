package org.altcha.altcha.v2;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

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
        var keyPrefixBuf  = hexToBytes(params.keyPrefix());
        var pw            = new PasswordBuffer(nonceBuf);
        var t0            = System.nanoTime();
        var counter       = counterStart;

        while (true) {
            var result = kdfFn.deriveKey(params, saltBuf, pw.setCounter(counter));
            if (startsWith(result.derivedKey(), keyPrefixBuf)) {
                return new Solution(counter, bytesToHex(result.derivedKey()),
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
     * @param kdfFn                   KDF to use when re-deriving (may be {@code null} if
     *                                {@code keySignature} is present)
     */
    public static VerifySolutionResult verifySolution(
            Challenge challenge,
            Solution solution,
            String hmacSignatureSecret,
            String hmacKeySignatureSecret,
            KeyDerivationFunction kdfFn) throws Exception {

        if (hmacSignatureSecret == null || hmacSignatureSecret.isBlank()) {
            throw new IllegalArgumentException("hmacSignatureSecret is required for v2 verification");
        }

        var t0     = System.nanoTime();
        var params = challenge.parameters();

        // 1. Expiry
        if (params.expiresAt() != null && params.expiresAt() < System.currentTimeMillis() / 1000) {
            return new VerifySolutionResult(false, true, null, null, elapsed(t0));
        }

        // 2. Signature present
        if (challenge.signature() == null || challenge.signature().isBlank()) {
            return new VerifySolutionResult(false, false, true, null, elapsed(t0));
        }

        // 3. Verify challenge signature
        var hmacAlgorithm = DEFAULT_HMAC_ALGORITHM;
        var expectedSig = hmacHex(hmacAlgorithm,
                canonicalJson(params).getBytes(StandardCharsets.UTF_8),
                hmacSignatureSecret);
        if (!constantTimeEqual(challenge.signature(), expectedSig)) {
            return new VerifySolutionResult(false, false, true, null, elapsed(t0));
        }

        // 4a. Fast path: key signature
        if (params.keySignature() != null && hmacKeySignatureSecret != null) {
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
        var nonceBuf = hexToBytes(params.nonce());
        var saltBuf  = hexToBytes(params.salt());
        var pw       = new PasswordBuffer(nonceBuf);
        var result   = kdfFn.deriveKey(params, saltBuf, pw.setCounter(solution.counter()));
        var rederived = bytesToHex(result.derivedKey());
        var valid     = constantTimeEqual(rederived, solution.derivedKey());
        return new VerifySolutionResult(valid, false, false, !valid, elapsed(t0));
    }

    /** Convenience overload with no key-signature secret. */
    public static VerifySolutionResult verifySolution(
            Challenge challenge, Solution solution,
            String hmacSignatureSecret, KeyDerivationFunction kdfFn) throws Exception {
        return verifySolution(challenge, solution, hmacSignatureSecret, null, kdfFn);
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
        var json = new JSONObject(
                new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8));
        var challengeObj  = json.getJSONObject("challenge");
        var paramsObj     = challengeObj.getJSONObject("parameters");
        var solutionObj   = json.getJSONObject("solution");

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
                paramsObj.has("data")        && !paramsObj.isNull("data")        ? parseDataMap(paramsObj.getJSONObject("data")) : null);

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
     * <p>Keys are sorted lexicographically (matching JS {@code Object.keys(obj).sort()}).
     * Null fields are omitted. This format is used for HMAC signing.</p>
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

    /** Recursively encodes a value as canonical JSON. Maps have keys sorted lexicographically. */
    @SuppressWarnings("unchecked")
    private static String encodeValue(Object value) {
        if (value instanceof String s) return jsonString(s);
        if (value instanceof Map<?, ?> m) {
            var sb = new StringBuilder("{");
            var first = true;
            for (var key : new TreeSet<>(((Map<String, ?>) m).keySet())) {
                if (!first) sb.append(',');
                first = false;
                sb.append(jsonString(key)).append(':').append(encodeValue(m.get(key)));
            }
            return sb.append('}').toString();
        }
        // Number, Boolean, null
        return String.valueOf(value);
    }

    /** Returns a properly JSON-escaped quoted string. */
    static String jsonString(String s) {
        var sb = new StringBuilder(s.length() + 2);
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
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else          sb.append(c);
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }

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

    public static String bytesToHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    private static long elapsed(long t0) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
    }

    private static Map<String, Object> parseDataMap(JSONObject obj) {
        var map = new LinkedHashMap<String, Object>();
        for (var key : obj.keySet()) {
            var val = obj.get(key);
            if (JSONObject.NULL.equals(val)) map.put(key, null);
            else map.put(key, val);
        }
        return map;
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
