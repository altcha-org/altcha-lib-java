package org.altcha.altcha.v2;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AltchaV2Test {

    private static final String HMAC_SECRET = "test-secret-key";

    // -------------------------------------------------------------------------
    // Canonical JSON
    // -------------------------------------------------------------------------

    @Test
    public void testCanonicalJsonMinimal() {
        var params = new Altcha.ChallengeParameters(
                "PBKDF2/SHA-256", "abcnonce", "defsalt",
                1000, 32, "00", null, null, null, null, null);
        var json = Altcha.canonicalJson(params);
        // Keys must be in alphabetical order; no null fields
        assertEquals(
                "{\"algorithm\":\"PBKDF2/SHA-256\",\"cost\":1000,\"keyLength\":32," +
                "\"keyPrefix\":\"00\",\"nonce\":\"abcnonce\",\"salt\":\"defsalt\"}",
                json);
    }

    @Test
    public void testCanonicalJsonWithOptionalFields() {
        var params = new Altcha.ChallengeParameters(
                "SHA-256", "n", "s", 500, 32, "0a",
                "keysig", 65536, 4, 1_700_000_000L, null);
        var json = Altcha.canonicalJson(params);
        // Verify all optional fields appear in sorted order
        assertTrue(json.contains("\"expiresAt\":1700000000"));
        assertTrue(json.contains("\"keySignature\":\"keysig\""));
        assertTrue(json.contains("\"memoryCost\":65536"));
        assertTrue(json.contains("\"parallelism\":4"));
        // Ensure alphabetical key order
        var algIdx    = json.indexOf("\"algorithm\"");
        var costIdx   = json.indexOf("\"cost\"");
        var expIdx    = json.indexOf("\"expiresAt\"");
        var keyLIdx   = json.indexOf("\"keyLength\"");
        var keyPIdx   = json.indexOf("\"keyPrefix\"");
        var keySIdx   = json.indexOf("\"keySignature\"");
        var memIdx    = json.indexOf("\"memoryCost\"");
        var nonceIdx  = json.indexOf("\"nonce\"");
        var paraIdx   = json.indexOf("\"parallelism\"");
        var saltIdx   = json.indexOf("\"salt\"");
        assertTrue(algIdx < costIdx && costIdx < expIdx && expIdx < keyLIdx
                && keyLIdx < keyPIdx && keyPIdx < keySIdx && keySIdx < memIdx
                && memIdx < nonceIdx && nonceIdx < paraIdx && paraIdx < saltIdx);
    }

    @Test
    public void testCanonicalJsonWithData() {
        var data = new LinkedHashMap<String, Object>();
        data.put("userId", "42");
        data.put("admin", true);
        var params = new Altcha.ChallengeParameters(
                "SHA-256", "n", "s", 100, 32, "00",
                null, null, null, null, data);
        var json = Altcha.canonicalJson(params);
        // data keys must also be sorted
        assertTrue(json.contains("\"data\":{\"admin\":true,\"userId\":\"42\"}"));
    }

    @Test
    public void testJsonStringEscaping() {
        assertEquals("\"hello\\\"world\"", Altcha.jsonString("hello\"world"));
        assertEquals("\"line\\nbreak\"",   Altcha.jsonString("line\nbreak"));
        assertEquals("\"tab\\there\"",     Altcha.jsonString("tab\there"));
    }

    // -------------------------------------------------------------------------
    // PasswordBuffer
    // -------------------------------------------------------------------------

    @Test
    public void testPasswordBufferUint32() {
        var nonce  = new byte[]{0x01, 0x02};
        var pw     = new Altcha.PasswordBuffer(nonce);
        var result = pw.setCounter(256);        // 0x00000100 big-endian
        assertEquals(6, result.length);
        assertEquals(0x01, result[0] & 0xFF);
        assertEquals(0x02, result[1] & 0xFF);
        assertEquals(0x00, result[2] & 0xFF);
        assertEquals(0x00, result[3] & 0xFF);
        assertEquals(0x01, result[4] & 0xFF);
        assertEquals(0x00, result[5] & 0xFF);
    }

    // -------------------------------------------------------------------------
    // PBKDF2 raw-bytes correctness
    // -------------------------------------------------------------------------

    @Test
    public void testPbkdf2KnownVector() throws Exception {
        // RFC 6070 test vector: PBKDF2-HMAC-SHA1 is the reference, but we test
        // that our implementation produces the same result as a second call
        // (self-consistency) and that identical inputs → identical outputs.
        var password = "password".getBytes(StandardCharsets.UTF_8);
        var salt     = "salt".getBytes(StandardCharsets.UTF_8);
        var dk1 = Altcha.pbkdf2Hmac("HmacSHA256", password, salt, 1000, 32);
        var dk2 = Altcha.pbkdf2Hmac("HmacSHA256", password, salt, 1000, 32);
        assertArrayEquals(dk1, dk2, "PBKDF2 must be deterministic");
        assertEquals(32, dk1.length);
    }

    @Test
    public void testPbkdf2DifferentPasswords() throws Exception {
        var salt = "salt".getBytes(StandardCharsets.UTF_8);
        var dk1  = Altcha.pbkdf2Hmac("HmacSHA256", "pw1".getBytes(StandardCharsets.UTF_8), salt, 100, 32);
        var dk2  = Altcha.pbkdf2Hmac("HmacSHA256", "pw2".getBytes(StandardCharsets.UTF_8), salt, 100, 32);
        assertFalse(java.util.Arrays.equals(dk1, dk2));
    }

    // -------------------------------------------------------------------------
    // createChallenge
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"PBKDF2/SHA-256", "PBKDF2/SHA-512", "SHA-256", "SHA-512"})
    public void testCreateChallenge(String algorithm) throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm(algorithm)
                .cost(100)
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);

        assertNotNull(challenge.parameters());
        assertEquals(algorithm, challenge.parameters().algorithm());
        assertNotNull(challenge.parameters().nonce());
        assertNotNull(challenge.parameters().salt());
        assertEquals(32, challenge.parameters().keyLength());
        assertNotNull(challenge.signature(), "challenge must be signed");
    }

    @Test
    public void testCreateChallengeUnsigned() throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10);
        var challenge = Altcha.createChallenge(opts);
        assertNull(challenge.signature(), "no secret → no signature");
    }

    @Test
    public void testCreateChallengeWithExpiry() throws Exception {
        var future = System.currentTimeMillis() / 1000 + 3600;
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .expiresAt(future)
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        assertEquals(future, challenge.parameters().expiresAt());
    }

    @Test
    public void testCreateChallengeWithData() throws Exception {
        var data = Map.<String, Object>of("userId", "123");
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .data(data)
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        assertEquals("123", challenge.parameters().data().get("userId"));
    }

    @Test
    public void testCreateChallengeDeterministic() throws Exception {
        // With a known counter, keyPrefix should equal the first half of the derived key.
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .counter(0)
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        // keyPrefix must not be the default "00" (it was computed from the actual derived key)
        assertNotEquals("00", challenge.parameters().keyPrefix(),
                "deterministic mode must derive keyPrefix from counter=0");
        assertEquals(32, challenge.parameters().keyPrefix().length(),
                "keyPrefix should be 16 bytes = 32 hex chars (keyLength/2 * 2)");
    }

    // -------------------------------------------------------------------------
    // solveChallenge
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"PBKDF2/SHA-256", "SHA-256"})
    public void testSolveChallenge(String algorithm) throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm(algorithm)
                .cost(100)
                .keyPrefix("00")       // ~1/256 chance each attempt
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf(algorithm);

        var solution = Altcha.solveChallenge(challenge, kdf);

        assertNotNull(solution);
        assertTrue(solution.counter() >= 0);
        assertNotNull(solution.derivedKey());
        assertTrue(solution.derivedKey().startsWith("00"),
                "derived key must start with keyPrefix '00'");
    }

    // -------------------------------------------------------------------------
    // verifySolution
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"PBKDF2/SHA-256", "SHA-256"})
    public void testVerifySolution(String algorithm) throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm(algorithm)
                .cost(100)
                .keyPrefix("00")
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf(algorithm);
        var solution  = Altcha.solveChallenge(challenge, kdf);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, kdf);

        assertTrue(result.verified());
        assertFalse(result.expired());
        assertFalse(result.invalidSignature());
        assertFalse(result.invalidSolution());
    }

    @Test
    public void testVerifySolutionExpired() throws Exception {
        var past = System.currentTimeMillis() / 1000 - 60;
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .expiresAt(past)
                .keyPrefix("00")
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, kdf);

        assertFalse(result.verified());
        assertTrue(result.expired());
        assertNull(result.invalidSignature());
        assertNull(result.invalidSolution());
    }

    @Test
    public void testVerifySolutionNoSignature() throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .keyPrefix("00");
        // Intentionally no hmacSignatureSecret → no signature
        var challenge = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, kdf);

        assertFalse(result.verified());
        assertFalse(result.expired());
        assertTrue(result.invalidSignature());
        assertNull(result.invalidSolution());
    }

    @Test
    public void testVerifySolutionTamperedParams() throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .keyPrefix("00")
                .hmacSignatureSecret(HMAC_SECRET);
        var original  = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(original, kdf);

        // Tamper: change cost in parameters (simulate attacker reducing difficulty)
        var tampered = new Altcha.Challenge(
                original.parameters().withKeyPrefix("ff"),
                original.signature());

        var result = Altcha.verifySolution(tampered, solution, HMAC_SECRET, kdf);
        assertFalse(result.verified());
        assertTrue(result.invalidSignature());
    }

    @Test
    public void testVerifySolutionWrongDerivedKey() throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .keyPrefix("00")
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        // Tamper: flip one character in the derived key
        var tamperedKey = solution.derivedKey().replace(solution.derivedKey().charAt(2), 'x');
        var tampered    = new Altcha.Solution(solution.counter(), tamperedKey, solution.time());

        var result = Altcha.verifySolution(challenge, tampered, HMAC_SECRET, kdf);
        assertFalse(result.verified());
        assertTrue(result.invalidSolution());
    }

    @Test
    public void testVerifySolutionWithKeySignature() throws Exception {
        // Deterministic mode: server knows the counter in advance, sets keySignature.
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .counter(5)
                .hmacSignatureSecret(HMAC_SECRET)
                .hmacKeySignatureSecret("key-signing-secret");
        var challenge = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf("SHA-256");

        assertNotNull(challenge.parameters().keySignature(), "keySignature must be set in deterministic mode");

        var solution = Altcha.solveChallenge(challenge, kdf);

        // Verify using key signature (fast path – no KDF re-invocation needed)
        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET,
                "key-signing-secret", null);
        assertTrue(result.verified());
    }

    // -------------------------------------------------------------------------
    // Base64 payload round-trip
    // -------------------------------------------------------------------------

    @Test
    public void testParseAndVerifyPayload() throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(100)
                .keyPrefix("00")
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        // Simulate what the client would submit
        var json = String.format(
                "{\"challenge\":{\"parameters\":{\"algorithm\":\"%s\",\"cost\":%d,\"keyLength\":%d," +
                "\"keyPrefix\":\"%s\",\"nonce\":\"%s\",\"salt\":\"%s\"},\"signature\":\"%s\"}," +
                "\"solution\":{\"counter\":%d,\"derivedKey\":\"%s\"}}",
                challenge.parameters().algorithm(),
                challenge.parameters().cost(),
                challenge.parameters().keyLength(),
                challenge.parameters().keyPrefix(),
                challenge.parameters().nonce(),
                challenge.parameters().salt(),
                challenge.signature(),
                solution.counter(),
                solution.derivedKey());
        var base64 = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));

        var result = Altcha.verifySolution(base64, HMAC_SECRET, kdf);
        assertTrue(result.verified());
    }

    // -------------------------------------------------------------------------
    // Fields hash
    // -------------------------------------------------------------------------

    @Test
    public void testVerifyFieldsHash() throws Exception {
        var formData = Map.of("name", "Alice", "email", "alice@example.com");
        var fields   = new String[]{"name", "email"};

        var combined = "Alice\nalice@example.com";
        var md    = java.security.MessageDigest.getInstance("SHA-256");
        var hash  = Altcha.bytesToHex(md.digest(combined.getBytes(StandardCharsets.UTF_8)));

        assertTrue(Altcha.verifyFieldsHash(formData, fields, hash, "SHA-256"));
    }

    // -------------------------------------------------------------------------
    // Server signature
    // -------------------------------------------------------------------------

    @Test
    public void testVerifyServerSignature() throws Exception {
        var verData = "score=0.9&verified=true&location.countryCode=DE";
        var md   = java.security.MessageDigest.getInstance("SHA-256");
        var hash = md.digest(verData.getBytes(StandardCharsets.UTF_8));
        var mac  = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(
                HMAC_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        var sig  = Altcha.bytesToHex(mac.doFinal(hash));

        var payload = new Altcha.ServerSignaturePayload(
                "SHA-256", null, null, verData, sig, true);
        var result  = Altcha.verifyServerSignature(payload, HMAC_SECRET);

        assertTrue(result.verified());
        assertEquals("DE", result.verificationData().getAdditionalField("location.countryCode"));
        assertEquals(0.9, result.verificationData().score(), 0.001);
    }

    // -------------------------------------------------------------------------
    // Require hmacSignatureSecret
    // -------------------------------------------------------------------------

    @Test
    public void testVerifySolutionRequiresHmacSecret() throws Exception {
        var params   = new Altcha.ChallengeParameters("SHA-256","n","s",10,32,"00",null,null,null,null,null);
        var challenge = new Altcha.Challenge(params, "sig");
        var solution  = new Altcha.Solution(0, "00aabbcc", null);
        var kdf       = Altcha.kdf("SHA-256");

        assertThrows(IllegalArgumentException.class,
                () -> Altcha.verifySolution(challenge, solution, null, kdf));
        assertThrows(IllegalArgumentException.class,
                () -> Altcha.verifySolution(challenge, solution, "", kdf));
    }
}
