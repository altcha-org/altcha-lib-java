package org.altcha.altcha.v1;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/**
 * ALTCHA v1 – simple hashcash-style proof-of-work.
 *
 * <p>Challenges are created by hashing {@code salt + number} with SHA-1/256/512.
 * Parameters (expiry, custom data) are embedded in the salt as a URL query string
 * and a trailing {@code &} delimiter prevents parameter-splicing attacks.</p>
 */
public final class Altcha {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static final long DEFAULT_MAX_NUMBER = 1_000_000L;
    public static final long DEFAULT_SALT_LENGTH = 12L;
    public static final Algorithm DEFAULT_ALGORITHM = Algorithm.SHA256;

    private Altcha() {}

    // -------------------------------------------------------------------------
    // Algorithm enum
    // -------------------------------------------------------------------------

    public enum Algorithm {
        SHA1("SHA-1"), SHA256("SHA-256"), SHA512("SHA-512");

        private final String name;

        Algorithm(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public String getHmacName() {
            return switch (this) {
                case SHA1   -> "HmacSHA1";
                case SHA256 -> "HmacSHA256";
                case SHA512 -> "HmacSHA512";
            };
        }

        public static Algorithm fromString(String name) {
            for (var algo : Algorithm.values()) {
                if (algo.name.equals(name)) return algo;
            }
            throw new IllegalArgumentException("No enum constant for algorithm: " + name);
        }
    }

    // -------------------------------------------------------------------------
    // Data types (records)
    // -------------------------------------------------------------------------

    /** A generated proof-of-work challenge sent to the client. */
    public record Challenge(
            String algorithm,
            String challenge,
            long maxnumber,
            String salt,
            String signature) {}

    /** The client's solved payload returned to the server for verification. */
    public record Payload(
            String algorithm,
            String challenge,
            long number,
            String salt,
            String signature) {}

    /** The result of brute-forcing a challenge (client-side). */
    public record Solution(int number, long took) {}

    /** Signed server-attestation payload from the ALTCHA Sentinel service. */
    public record ServerSignaturePayload(
            Algorithm algorithm,
            String apiKey,
            String id,
            String verificationData,
            String signature,
            boolean verified) {}

    /** Result of verifying a server-attestation payload. */
    public record ServerSignatureVerification(
            boolean verified,
            ServerSignatureVerificationData verificationData) {}

    /** Parsed verification data from the ALTCHA Sentinel service. */
    /**
     * @param country @deprecated Use {@code getAdditionalField("location.countryCode")} with Sentinel.
     * @param detectedLanguage @deprecated Use {@code getAdditionalField("text.language")} with Sentinel.
     */
    public record ServerSignatureVerificationData(
            String classification,
            String country,
            String detectedLanguage,
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
    }

    // -------------------------------------------------------------------------
    // Challenge options (mutable builder)
    // -------------------------------------------------------------------------

    public static final class ChallengeOptions {
        public Algorithm algorithm = DEFAULT_ALGORITHM;
        public long maxNumber = DEFAULT_MAX_NUMBER;
        public long saltLength = DEFAULT_SALT_LENGTH;
        public boolean secureRandomNumber = false;
        public String hmacKey;
        public String salt;
        public Long number;
        public Long expires;
        public final Map<String, String> params = new LinkedHashMap<>();

        public ChallengeOptions algorithm(Algorithm algorithm)           { this.algorithm = algorithm; return this; }
        public ChallengeOptions maxNumber(long maxNumber)               { this.maxNumber = maxNumber; return this; }
        public ChallengeOptions saltLength(long saltLength)             { this.saltLength = saltLength; return this; }
        public ChallengeOptions secureRandomNumber(boolean secure)      { this.secureRandomNumber = secure; return this; }
        public ChallengeOptions hmacKey(String hmacKey)                 { this.hmacKey = hmacKey; return this; }
        public ChallengeOptions salt(String salt)                       { this.salt = salt; return this; }
        public ChallengeOptions number(Long number)                     { this.number = number; return this; }
        public ChallengeOptions expires(Long expires)                   { this.expires = expires; return this; }
        public ChallengeOptions expiresInSeconds(long seconds)          { this.expires = System.currentTimeMillis() / 1000 + seconds; return this; }
        public ChallengeOptions param(String key, String value)         { this.params.put(key, value); return this; }
    }

    // -------------------------------------------------------------------------
    // Random helpers
    // -------------------------------------------------------------------------

    public static byte[] randomBytes(int length) {
        var bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static int randomInt(long max) {
        if (max <= 0) throw new IllegalArgumentException("max must be positive");
        return ThreadLocalRandom.current().nextInt((int) Math.min(max, Integer.MAX_VALUE));
    }

    public static int randomIntSecure(long max) {
        if (max <= 0) throw new IllegalArgumentException("max must be positive");
        return SECURE_RANDOM.nextInt((int) Math.min(max, Integer.MAX_VALUE));
    }

    // -------------------------------------------------------------------------
    // Crypto helpers
    // -------------------------------------------------------------------------

    public static byte[] hash(Algorithm algorithm, byte[] data) throws Exception {
        return MessageDigest.getInstance(algorithm.getName()).digest(data);
    }

    public static String hashHex(Algorithm algorithm, String data) throws Exception {
        return bytesToHex(hash(algorithm, data.getBytes(StandardCharsets.UTF_8)));
    }

    public static byte[] hmacHash(Algorithm algorithm, byte[] data, byte[] key) throws Exception {
        var mac = Mac.getInstance(algorithm.getHmacName());
        mac.init(new SecretKeySpec(key, algorithm.getHmacName()));
        return mac.doFinal(data);
    }

    public static String hmacHex(Algorithm algorithm, byte[] data, String key) throws Exception {
        return bytesToHex(hmacHash(algorithm, data, key.getBytes(StandardCharsets.UTF_8)));
    }

    // -------------------------------------------------------------------------
    // Challenge creation
    // -------------------------------------------------------------------------

    public static Challenge createChallenge(ChallengeOptions options) throws Exception {
        var algorithm = options.algorithm != null ? options.algorithm : DEFAULT_ALGORITHM;
        var maxNumber = options.maxNumber > 0 ? options.maxNumber : DEFAULT_MAX_NUMBER;
        var saltLength = options.saltLength > 0 ? options.saltLength : DEFAULT_SALT_LENGTH;

        var params = new LinkedHashMap<>(options.params);
        if (options.expires != null) params.put("expires", options.expires.toString());

        var salt = options.salt != null ? options.salt
                : bytesToHex(randomBytes((int) saltLength));
        if (!params.isEmpty()) salt += "?" + encodeParams(params);
        if (!salt.endsWith("&")) salt += "&";

        var number = options.number != null ? options.number
                : (options.secureRandomNumber ? randomIntSecure(maxNumber) : randomInt(maxNumber));
        var challengeStr = hashHex(algorithm, salt + number);
        var signature   = hmacHex(algorithm, challengeStr.getBytes(StandardCharsets.UTF_8), options.hmacKey);

        return new Challenge(algorithm.getName(), challengeStr, maxNumber, salt, signature);
    }

    // -------------------------------------------------------------------------
    // Solution verification
    // -------------------------------------------------------------------------

    public static boolean verifySolution(Payload payload, String hmacKey, boolean checkExpires) throws Exception {
        if (payload.algorithm() == null || payload.algorithm().isBlank()) return false;
        if (payload.challenge() == null || payload.challenge().isBlank()) return false;
        if (payload.salt()      == null || payload.salt().isBlank())      return false;
        if (payload.signature() == null || payload.signature().isBlank()) return false;
        return verifySolutionInternal(payload, hmacKey, checkExpires);
    }

    public static boolean verifySolution(String base64Payload, String hmacKey, boolean checkExpires) throws Exception {
        var json = new JSONObject(new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8));
        if (!json.has("algorithm") || !json.has("challenge") || !json.has("number")
                || !json.has("salt") || !json.has("signature")) return false;

        var payload = new Payload(
                json.getString("algorithm"),
                json.getString("challenge"),
                json.getLong("number"),
                json.getString("salt"),
                json.getString("signature"));
        return verifySolutionInternal(payload, hmacKey, checkExpires);
    }

    private static boolean verifySolutionInternal(Payload payload, String hmacKey, boolean checkExpires) throws Exception {
        var params = extractParams(payload.salt());
        if (checkExpires) {
            var expires = params.get("expires");
            if (expires != null && System.currentTimeMillis() / 1000 > Long.parseLong(expires)) return false;
        }

        var opts = new ChallengeOptions()
                .algorithm(Algorithm.fromString(payload.algorithm()))
                .hmacKey(hmacKey)
                .number(payload.number())
                .salt(payload.salt());
        var expected = createChallenge(opts);

        return expected.challenge().equals(payload.challenge())
                && expected.signature().equals(payload.signature());
    }

    // -------------------------------------------------------------------------
    // Fields hash verification
    // -------------------------------------------------------------------------

    public static boolean verifyFieldsHash(Map<String, String> formData, String[] fields,
            String fieldsHash, Algorithm algorithm) throws Exception {
        var sb = new StringBuilder();
        for (var field : fields) {
            var value = formData.get(field);
            if (value != null) sb.append(value);
            sb.append('\n');
        }
        return hashHex(algorithm, sb.toString().trim()).equals(fieldsHash);
    }

    // -------------------------------------------------------------------------
    // Server signature verification
    // -------------------------------------------------------------------------

    public static ServerSignatureVerification verifyServerSignature(ServerSignaturePayload payload,
            String hmacKey) throws Exception {
        if (payload.algorithm() == null || payload.verificationData() == null
                || payload.verificationData().isBlank() || payload.signature() == null
                || payload.signature().isBlank()) {
            return new ServerSignatureVerification(false, null);
        }
        return verifyServerSignatureInternal(payload, hmacKey);
    }

    public static ServerSignatureVerification verifyServerSignature(String base64Payload,
            String hmacKey) throws Exception {
        var json = new JSONObject(new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8));
        if (!json.has("algorithm") || !json.has("verificationData")
                || !json.has("signature") || !json.has("verified")) {
            return new ServerSignatureVerification(false, null);
        }

        var payload = new ServerSignaturePayload(
                Algorithm.fromString(json.getString("algorithm")),
                json.optString("apiKey", null),
                json.optString("id", null),
                json.getString("verificationData"),
                json.getString("signature"),
                json.getBoolean("verified"));
        return verifyServerSignatureInternal(payload, hmacKey);
    }

    private static ServerSignatureVerification verifyServerSignatureInternal(
            ServerSignaturePayload payload, String hmacKey) throws Exception {
        var hash = hash(payload.algorithm(), payload.verificationData().getBytes(StandardCharsets.UTF_8));
        var expectedSig = hmacHex(payload.algorithm(), hash, hmacKey);
        var verificationData = extractVerificationData(payload.verificationData());
        var now = System.currentTimeMillis() / 1000;
        var verified = payload.verified()
                && verificationData.verified()
                && (verificationData.expire() == null || verificationData.expire() > now)
                && payload.signature().equals(expectedSig);
        return new ServerSignatureVerification(verified, verificationData);
    }

    private static ServerSignatureVerificationData extractVerificationData(String raw) throws Exception {
        var params = extractParams(raw);
        var predefined = Set.of("classification", "country", "detectedLanguage", "email",
                "expire", "fields", "fieldsHash", "ipAddress", "reasons", "score", "time", "verified");
        var extra = new LinkedHashMap<String, String>();
        for (var e : params.entrySet()) {
            if (!predefined.contains(e.getKey())) extra.put(e.getKey(), e.getValue());
        }
        return new ServerSignatureVerificationData(
                params.get("classification"),
                params.get("country"),
                params.get("detectedLanguage"),
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
    // Challenge solver (client-side utility)
    // -------------------------------------------------------------------------

    public static Solution solveChallenge(String challenge, String salt, Algorithm algorithm,
            long max, long start) throws Exception {
        if (algorithm == null) algorithm = DEFAULT_ALGORITHM;
        if (max  <= 0) max   = DEFAULT_MAX_NUMBER;
        if (start < 0) start = 0;

        var t0 = System.nanoTime();
        for (var n = start; n <= max; n++) {
            if (hashHex(algorithm, salt + n).equals(challenge)) {
                return new Solution((int) n, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0));
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Parameter extraction
    // -------------------------------------------------------------------------

    public static Map<String, String> extractParams(String salt) throws Exception {
        var result = new LinkedHashMap<String, String>();
        // Use the segment after the last '?' if present; otherwise parse the whole string.
        // This supports both salt format ("hexsalt?key=val&") and verificationData ("key=val&key2=val2").
        var parts    = salt.split("\\?");
        var paramStr = parts[parts.length - 1];
        for (var pair : paramStr.split("&")) {
            var kv = pair.split("=", 2);
            if (kv.length == 2) {
                result.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                           URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
            }
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Private utilities
    // -------------------------------------------------------------------------

    private static String encodeParams(Map<String, String> params) throws Exception {
        var sb = new StringBuilder();
        for (var e : params.entrySet()) {
            if (!sb.isEmpty()) sb.append('&');
            sb.append(URLEncoder.encode(e.getKey(),   StandardCharsets.UTF_8))
              .append('=')
              .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    static String bytesToHex(byte[] bytes) {
        var sb = new StringBuilder(2 * bytes.length);
        for (var b : bytes) {
            var hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) sb.append('0');
            sb.append(hex);
        }
        return sb.toString();
    }
}
