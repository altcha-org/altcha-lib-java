package org.altcha.altcha;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/**
 * The `Altcha` class provides functionality for generating and verifying
 * cryptographic challenges.
 * It supports different algorithms for hashing and HMAC, and offers utilities
 * for managing challenge options,
 * solving challenges, and verifying server signatures.
 */
public class Altcha {
    // Static SecureRandom instance for thread-safe reuse
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Enumeration for supported hashing and HMAC algorithms.
     */
    public enum Algorithm {
        SHA1("SHA-1"), SHA256("SHA-256"), SHA512("SHA-512");

        private final String name;

        Algorithm(String name) {
            this.name = name;
        }

        /**
         * Returns the name of the algorithm.
         * 
         * @return The algorithm name.
         */
        public String getName() {
            return name;
        }

        /**
         * Returns the HMAC name for the algorithm.
         * 
         * @return The HMAC algorithm name.
         */
        public String getHmacName() {
            switch (this) {
                case SHA1:
                    return "HmacSHA1";
                case SHA256:
                    return "HmacSHA256";
                case SHA512:
                    return "HmacSHA512";
                default:
                    throw new IllegalArgumentException("Unsupported hmac algorithm: " + name);
            }
        }

        /**
         * Converts a string representation of the algorithm to an `Algorithm` enum.
         * 
         * @param name The algorithm name.
         * @return The corresponding `Algorithm` enum.
         * @throws IllegalArgumentException If no matching algorithm is found.
         */
        public static Algorithm fromString(String name) {
            for (Algorithm algo : Algorithm.values()) {
                if (algo.name.equals(name)) {
                    return algo;
                }
            }
            throw new IllegalArgumentException("No enum constant for algorithm: " + name);
        }
    }

    public static final Long DEFAULT_MAX_NUMBER = 1_000_000L;
    public static final Long DEFAULT_SALT_LENGTH = 12L;
    public static final Algorithm DEFAULT_ALGORITHM = Algorithm.SHA256;

    /**
     * Options for creating a challenge.
     */
    public static class ChallengeOptions {
        public Algorithm algorithm = DEFAULT_ALGORITHM;
        public Long maxNumber = DEFAULT_MAX_NUMBER;
        public Long saltLength = DEFAULT_SALT_LENGTH;
        public Boolean secureRandomNumber = false;
        public String hmacKey;
        public String salt;
        public Long number;
        public Long expires;
        public Map<String, String> params = new HashMap<>();

        public ChallengeOptions setAlgorithm(Algorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public ChallengeOptions setMaxNumber(Long maxNumber) {
            this.maxNumber = maxNumber;
            return this;
        }

        public ChallengeOptions setSaltLength(Long saltLength) {
            this.saltLength = saltLength;
            return this;
        }

        public ChallengeOptions setSecureRandomNumber(Boolean secureRandomNumber) {
            this.secureRandomNumber = secureRandomNumber;
            return this;
        }

        public ChallengeOptions setHmacKey(String hmacKey) {
            this.hmacKey = hmacKey;
            return this;
        }

        public ChallengeOptions setSalt(String salt) {
            this.salt = salt;
            return this;
        }

        public ChallengeOptions setNumber(Long number) {
            this.number = number;
            return this;
        }

        public ChallengeOptions setExpires(Long expires) {
            this.expires = expires;
            return this;
        }

        public ChallengeOptions setExpiresInSeconds(long seconds) {
            this.expires = System.currentTimeMillis() / 1000 + seconds;
            return this;
        }

        public ChallengeOptions addParam(String key, String value) {
            this.params.put(key, value);
            return this;
        }
    }

    /**
     * Represents a cryptographic challenge.
     */
    public static class Challenge {
        public String algorithm;
        public String challenge;
        public Long maxnumber;
        public String salt;
        public String signature;
    }

    /**
     * Represents the payload of a challenge solution.
     */
    public static class Payload {
        public String algorithm;
        public String challenge;
        public Long number;
        public String salt;
        public String signature;
    }

    /**
     * Represents the payload for server signature verification.
     */
    public static class ServerSignaturePayload {
        public Algorithm algorithm;
        public String verificationData;
        public String signature;
        public boolean verified;
    }

    /**
     * Represents the result of server signature verification.
     */
    public static class ServerSignatureVerification {
        public boolean verified;
        public ServerSignatureVerificationData verificationData;
    }

    /**
     * Contains details about server signature verification.
     */
    public static class ServerSignatureVerificationData {
        public String classification;
        public String country;
        public String detectedLanguage;
        public String email;
        public Long expire;
        public String[] fields;
        public String fieldsHash;
        public String ipAddress;
        public String[] reasons;
        public double score;
        public long time;
        public boolean verified;
    }

    /**
     * Represents a solution to a challenge.
     */
    public static class Solution {
        public int number;
        public long took;
    }

    /**
     * Generates a byte array of random values.
     * 
     * @param length The length of the byte array.
     * @return The generated byte array.
     */
    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates a random integer within the specified range.
     * 
     * @param max The upper bound (exclusive) of the random integer.
     * @return The generated random integer.
     */
    public static int randomInt(long max) {
        if (max <= 0) {
            throw new IllegalArgumentException("Max must be positive");
        }
        // Ensure we don't overflow when casting to int
        int intMax = (int) Math.min(max, Integer.MAX_VALUE);
        return ThreadLocalRandom.current().nextInt(intMax);
    }

    /**
     * Generates a secure random integer within the specified range.
     * 
     * @param max The upper bound (exclusive) of the random integer.
     * @return The generated random integer.
     */
    public static int randomIntSecure(long max) {
        if (max <= 0) {
            throw new IllegalArgumentException("Max must be positive");
        }
        // Ensure we don't overflow when casting to int
        int intMax = (int) Math.min(max, Integer.MAX_VALUE);
        return SECURE_RANDOM.nextInt(intMax);
    }

    /**
     * Computes the hash of the given data using the specified algorithm, returning
     * the result as a hex string.
     * 
     * @param algorithm The hashing algorithm.
     * @param data      The data to hash.
     * @return The hexadecimal representation of the hash.
     * @throws Exception If an error occurs during hashing.
     */
    public static String hashHex(Algorithm algorithm, String data) throws Exception {
        byte[] hash = hash(algorithm, data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    /**
     * Computes the hash of the given data using the specified algorithm.
     * 
     * @param algorithm The hashing algorithm.
     * @param data      The data to hash.
     * @return The hash value as a byte array.
     * @throws Exception If an error occurs during hashing.
     */
    public static byte[] hash(Algorithm algorithm, byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getName());
        return digest.digest(data);
    }

    /**
     * Computes the HMAC of the given data using the specified algorithm and key,
     * returning the result as a hex string.
     * 
     * @param algorithm The HMAC algorithm.
     * @param data      The data to HMAC.
     * @param key       The HMAC key.
     * @return The hexadecimal representation of the HMAC.
     * @throws Exception If an error occurs during HMAC computation.
     */
    public static String hmacHex(Algorithm algorithm, byte[] data, String key) throws Exception {
        byte[] hash = hmacHash(algorithm, data, key.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    /**
     * Computes the HMAC of the given data using the specified algorithm and key.
     * 
     * @param algorithm The HMAC algorithm.
     * @param data      The data to HMAC.
     * @param key       The HMAC key.
     * @return The HMAC value as a byte array.
     * @throws Exception If an error occurs during HMAC computation.
     */
    public static byte[] hmacHash(Algorithm algorithm, byte[] data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance(algorithm.getHmacName());
        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm.getName());
        mac.init(secretKey);
        return mac.doFinal(data);
    }

    /**
     * Creates a challenge with the given options.
     * 
     * @param options The challenge options.
     * @return The created challenge.
     * @throws Exception If an error occurs during challenge creation.
     */
    public static Challenge createChallenge(ChallengeOptions options) throws Exception {
        Algorithm algorithm = options.algorithm != null ? options.algorithm : DEFAULT_ALGORITHM;
        long maxNumber = options.maxNumber != null ? options.maxNumber : DEFAULT_MAX_NUMBER;
        long saltLength = options.saltLength != null ? options.saltLength : DEFAULT_SALT_LENGTH;

        Map<String, String> params = options.params;
        if (options.expires != null) {
            params.put("expires", options.expires.toString());
        }

        String salt = options.salt != null ? options.salt : bytesToHex(randomBytes((int) saltLength));
        if (!params.isEmpty()) {
            salt += "?" + encodeParams(params);
        }

        long number = options.number != null ? options.number
                : (options.secureRandomNumber ? randomIntSecure(maxNumber) : randomInt(maxNumber));
        String challengeStr = hashHex(algorithm, salt + number);

        String signature = hmacHex(algorithm, challengeStr.getBytes(StandardCharsets.UTF_8), options.hmacKey);

        Challenge challenge = new Challenge();
        challenge.algorithm = algorithm.getName();
        challenge.challenge = challengeStr;
        challenge.maxnumber = maxNumber;
        challenge.salt = salt;
        challenge.signature = signature;

        return challenge;
    }

    /**
     * Verifies a challenge solution using the provided payload and HMAC key.
     * 
     * @param payload      The challenge payload.
     * @param hmacKey      The HMAC key used for verification.
     * @param checkExpires Whether to check the expiration of the challenge.
     * @return `true` if the solution is valid; `false` otherwise.
     * @throws Exception If an error occurs during verification.
     */
    public static boolean verifySolution(Payload payload, String hmacKey, boolean checkExpires) throws Exception {
        List<String> requiredFields = Arrays.asList("algorithm", "challenge", "number", "salt", "signature");
        if (!checkRequiredFields(payload, requiredFields)) {
            return false;
        }
        return verifySolutionInternal(payload, hmacKey, checkExpires);
    }

    /**
     * Verifies a challenge solution encoded in Base64 using the provided HMAC key.
     * 
     * @param base64Payload The Base64-encoded payload.
     * @param hmacKey       The HMAC key used for verification.
     * @param checkExpires  Whether to check the expiration of the challenge.
     * @return `true` if the solution is valid; `false` otherwise.
     * @throws Exception If an error occurs during verification.
     */
    public static boolean verifySolution(String base64Payload, String hmacKey, boolean checkExpires) throws Exception {
        String decodedPayload = new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8);
        JSONObject jsonObject = new JSONObject(decodedPayload);

        List<String> requiredFields = Arrays.asList("algorithm", "challenge", "number", "salt", "signature");
        if (!checkRequiredFields(jsonObject, requiredFields)) {
            return false;
        }

        Payload parsedPayload = new Payload();
        parsedPayload.algorithm = jsonObject.getString("algorithm");
        parsedPayload.challenge = jsonObject.getString("challenge");
        parsedPayload.number = jsonObject.getLong("number");
        parsedPayload.salt = jsonObject.getString("salt");
        parsedPayload.signature = jsonObject.getString("signature");

        return verifySolutionInternal(parsedPayload, hmacKey, checkExpires);
    }

    private static boolean verifySolutionInternal(Payload payload, String hmacKey, boolean checkExpires)
            throws Exception {
        Map<String, String> params = extractParams(payload.salt);
        String expires = params.get("expires");

        if (checkExpires && expires != null) {
            long expireTime = Long.parseLong(expires);
            long now = System.currentTimeMillis() / 1000;
            if (now > expireTime) {
                return false;
            }
        }

        ChallengeOptions options = new ChallengeOptions();
        options.algorithm = Algorithm.fromString(payload.algorithm);
        options.hmacKey = hmacKey;
        options.number = payload.number;
        options.salt = payload.salt;

        Challenge expectedChallenge = createChallenge(options);

        return expectedChallenge.challenge.equals(payload.challenge) &&
                expectedChallenge.signature.equals(payload.signature);
    }

    /**
     * Verifies the hash of specified fields in the provided form data.
     * 
     * @param formData   The form data.
     * @param fields     The fields to include in the hash.
     * @param fieldsHash The expected hash of the fields.
     * @param algorithm  The hashing algorithm.
     * @return `true` if the computed hash matches the expected hash; `false`
     *         otherwise.
     * @throws Exception If an error occurs during hashing.
     */
    public static boolean verifyFieldsHash(Map<String, String> formData, String[] fields, String fieldsHash,
            Algorithm algorithm) throws Exception {
        StringBuilder joinedData = new StringBuilder();
        for (String field : fields) {
            String value = formData.get(field);
            if (value != null) {
                joinedData.append(value);
            }
            joinedData.append("\n");
        }

        String computedHash = hashHex(algorithm, joinedData.toString().trim());
        return computedHash.equals(fieldsHash);
    }

    /**
     * Verifies a server signature using the provided payload and HMAC key.
     * 
     * @param payload The server signature payload.
     * @param hmacKey The HMAC key used for verification.
     * @return The result of the verification.
     * @throws Exception If an error occurs during verification.
     */
    public static ServerSignatureVerification verifyServerSignature(ServerSignaturePayload payload, String hmacKey)
            throws Exception {
        List<String> requiredFields = Arrays.asList("algorithm", "verificationData", "signature", "verified");
        if (!checkRequiredFields(payload, requiredFields)) {
            ServerSignatureVerification result = new ServerSignatureVerification();
            result.verified = false;
            return result;
        }
        return verifyServerSignatureInternal(payload, hmacKey);
    }

    /**
     * Verifies a server signature encoded in Base64 using the provided HMAC key.
     * 
     * @param base64Payload The Base64-encoded payload.
     * @param hmacKey       The HMAC key used for verification.
     * @return The result of the verification.
     * @throws Exception If an error occurs during verification.
     */
    public static ServerSignatureVerification verifyServerSignature(String base64Payload, String hmacKey)
            throws Exception {
        String decodedPayload = new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8);
        JSONObject jsonObject = new JSONObject(decodedPayload);

        List<String> requiredFields = Arrays.asList("algorithm", "verificationData", "signature", "verified");
        if (!checkRequiredFields(jsonObject, requiredFields)) {
            ServerSignatureVerification result = new ServerSignatureVerification();
            result.verified = false;
            return result;
        }

        ServerSignaturePayload parsedPayload = new ServerSignaturePayload();
        parsedPayload.algorithm = Algorithm.fromString(jsonObject.getString("algorithm"));
        parsedPayload.verificationData = jsonObject.getString("verificationData");
        parsedPayload.signature = jsonObject.getString("signature");
        parsedPayload.verified = jsonObject.getBoolean("verified");

        return verifyServerSignatureInternal(parsedPayload, hmacKey);
    }

    private static ServerSignatureVerification verifyServerSignatureInternal(ServerSignaturePayload payload,
            String hmacKey)
            throws Exception {
        byte[] hash = hash(payload.algorithm, payload.verificationData.getBytes(StandardCharsets.UTF_8));
        String expectedSignature = hmacHex(payload.algorithm, hash, hmacKey);
        ServerSignatureVerification result = new ServerSignatureVerification();

        result.verificationData = extractVerificationData(payload.verificationData);

        long now = System.currentTimeMillis() / 1000;

        result.verified = payload.verified &&
                result.verificationData.verified &&
                (result.verificationData.expire == null || result.verificationData.expire > now) &&
                payload.signature.equals(expectedSignature);

        return result;
    }

    private static ServerSignatureVerificationData extractVerificationData(String verificationDataStr)
            throws Exception {
        Map<String, String> params = extractParams(verificationDataStr);

        ServerSignatureVerificationData verificationData = new ServerSignatureVerificationData();
        verificationData.classification = params.get("classification");
        verificationData.country = params.get("country");
        verificationData.detectedLanguage = params.get("detectedLanguage");
        verificationData.email = params.get("email");
        verificationData.expire = params.containsKey("expire") ? Long.parseLong(params.get("expire")) : null;
        verificationData.fields = params.containsKey("fields") ? params.get("fields").split(",") : null;
        verificationData.fieldsHash = params.get("fieldsHash");
        verificationData.ipAddress = params.get("ipAddress");
        verificationData.reasons = params.containsKey("reasons") ? params.get("reasons").split(",") : null;
        verificationData.score = params.containsKey("score") ? Double.parseDouble(params.get("score")) : 0.0;
        verificationData.time = params.containsKey("time") ? Long.parseLong(params.get("time")) : 0L;
        verificationData.verified = Boolean.parseBoolean(params.get("verified"));

        return verificationData;
    }

    /**
     * Solves a challenge by finding the number that produces the expected hash.
     * 
     * @param challenge The challenge string.
     * @param salt      The salt used in the challenge.
     * @param algorithm The hashing algorithm.
     * @param max       The maximum number to check.
     * @param start     The starting number.
     * @return The solution, or `null` if no solution is found.
     * @throws Exception If an error occurs during solving.
     */
    public static Solution solveChallenge(String challenge, String salt, Algorithm algorithm, long max, long start)
            throws Exception {
        if (algorithm == null) {
            algorithm = DEFAULT_ALGORITHM;
        }
        if (max <= 0) {
            max = DEFAULT_MAX_NUMBER.intValue();
        }
        if (start < 0) {
            start = 0;
        }

        long startTime = System.nanoTime();

        for (long n = start; n <= max; n++) {
            String hash = hashHex(algorithm, salt + n);
            if (hash.equals(challenge)) {
                long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
                Solution solution = new Solution();
                solution.number = (int) n;
                solution.took = took;
                return solution;
            }
        }

        return null;
    }

    /**
     * Extracts query parameters from a salt string.
     * 
     * @param salt The salt string containing query parameters.
     * @return A map of query parameters.
     * @throws Exception If an error occurs during extraction.
     */
    public static Map<String, String> extractParams(String salt) throws Exception {
        Map<String, String> params = new HashMap<>();
        String[] splitSalt = salt.split("\\?");
        if (splitSalt.length >= 1) {
            String[] paramPairs = splitSalt[splitSalt.length - 1].split("&");
            for (String paramPair : paramPairs) {
                String[] keyValue = paramPair.split("=");
                if (keyValue.length == 2) {
                    params.put(URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8.name()),
                            URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8.name()));
                }
            }
        }
        return params;
    }

    private static boolean checkRequiredFields(JSONObject jsonObject, List<String> requiredFields) {
        for (String field : requiredFields) {
            if (!jsonObject.has(field)) {
                return false;
            }
            Object value = jsonObject.get(field);
            if (value instanceof String && ((String) value).trim().isEmpty()) {
                return false;
            }
        }
        return true;
    }

    private static boolean checkRequiredFields(Object obj, List<String> requiredFields) {
        try {
            for (String field : requiredFields) {
                Field declaredField = obj.getClass().getDeclaredField(field);
                declaredField.setAccessible(true);
                Object value = declaredField.get(obj);
                if (value == null) {
                    return false;
                }
                if (value instanceof String && ((String) value).trim().isEmpty()) {
                    return false;
                }
            }
        } catch (NoSuchFieldException e) {
            return false;
        } catch (IllegalAccessException e) {
            return false;
        }
        return true;
    }

    private static String encodeParams(Map<String, String> params) throws Exception {
        StringBuilder encodedParams = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (encodedParams.length() > 0) {
                encodedParams.append("&");
            }
            encodedParams.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8.name()))
                    .append("=")
                    .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name()));
        }
        return encodedParams.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}