package org.altcha.altcha;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

public class Altcha {

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

    public static class ChallengeOptions {
        public Algorithm algorithm = DEFAULT_ALGORITHM;
        public Long maxNumber = DEFAULT_MAX_NUMBER;
        public Long saltLength = DEFAULT_SALT_LENGTH;
        public String hmacKey;
        public String salt;
        public Long number;
        public Long expires;
        public Map<String, String> params = new HashMap<>();
    }

    public static class Challenge {
        public String algorithm;
        public String challenge;
        public Long maxnumber;
        public String salt;
        public String signature;
    }

    public static class Payload {
        public String algorithm;
        public String challenge;
        public Long number;
        public String salt;
        public String signature;
    }

    public static class ServerSignaturePayload {
        public Algorithm algorithm;
        public String verificationData;
        public String signature;
        public boolean verified;
    }

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

    public static class Solution {
        public int number;
        public long took;
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static int randomInt(long max) {
        SecureRandom random = new SecureRandom();
        return random.nextInt((int) max);
    }

    public static String hashHex(Algorithm algorithm, String data) throws Exception {
        byte[] hash = hash(algorithm, data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    public static byte[] hash(Algorithm algorithm, byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getName());
        return digest.digest(data);
    }

    public static String hmacHex(Algorithm algorithm, byte[] data, String key) throws Exception {
        byte[] hash = hmacHash(algorithm, data, key.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    public static byte[] hmacHash(Algorithm algorithm, byte[] data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance(algorithm.getHmacName());
        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm.getName());
        mac.init(secretKey);
        return mac.doFinal(data);
    }

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

        long number = options.number != null ? options.number : randomInt(maxNumber);
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

    public static boolean verifySolution(Payload payload, String hmacKey, boolean checkExpires) throws Exception {
        return verifySolutionInternal(payload, hmacKey, checkExpires);
    }

    public static boolean verifySolution(String base64Payload, String hmacKey, boolean checkExpires) throws Exception {
        // Decode and parse the JSON
        String decodedPayload = new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8);
        JSONObject jsonObject = new JSONObject(decodedPayload);

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
        // Extract parameters from the salt
        Map<String, String> params = extractParams(payload.salt);
        String expires = params.get("expires");

        // Check if the solution has expired
        if (checkExpires && expires != null) {
            long expireTime = Long.parseLong(expires);
            if (System.currentTimeMillis() > expireTime) {
                return false;
            }
        }

        // Create the expected challenge
        ChallengeOptions options = new ChallengeOptions();
        options.algorithm = Algorithm.fromString(payload.algorithm);
        options.hmacKey = hmacKey;
        options.number = payload.number;
        options.salt = payload.salt;

        Challenge expectedChallenge = createChallenge(options);

        // Compare the provided challenge and signature with the expected values
        return expectedChallenge.challenge.equals(payload.challenge) &&
                expectedChallenge.signature.equals(payload.signature);
    }

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

    public static boolean verifyServerSignature(ServerSignaturePayload payload, String hmacKey) throws Exception {
        return verifyServerSignatureInternal(payload, hmacKey);
    }

    public static boolean verifyServerSignature(String base64Payload, String hmacKey) throws Exception {
        // Decode and parse the JSON
        String decodedPayload = new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8);
        JSONObject jsonObject = new JSONObject(decodedPayload);

        ServerSignaturePayload parsedPayload = new ServerSignaturePayload();
        parsedPayload.algorithm = Algorithm.fromString(jsonObject.getString("algorithm"));
        parsedPayload.verificationData = jsonObject.getString("verificationData");
        parsedPayload.signature = jsonObject.getString("signature");
        parsedPayload.verified = jsonObject.getBoolean("verified");

        return verifyServerSignatureInternal(parsedPayload, hmacKey);
    }

    private static boolean verifyServerSignatureInternal(ServerSignaturePayload payload, String hmacKey)
            throws Exception {
        // Calculate expected signature
        byte[] hash = hash(payload.algorithm, payload.verificationData.getBytes(StandardCharsets.UTF_8));
        String expectedSignature = hmacHex(payload.algorithm, hash, hmacKey);

        // Extract verification data
        ServerSignatureVerificationData verificationData = extractVerificationData(payload.verificationData);

        // Verify the signature
        long now = System.currentTimeMillis();

        System.out.println(verificationData.verified);

        boolean isVerified = payload.verified &&
                verificationData.verified &&
                (verificationData.expire == null || verificationData.expire > now) &&
                payload.signature.equals(expectedSignature);

        return isVerified;
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

        System.out.println(params.get("verified"));

        return verificationData;
    }

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
