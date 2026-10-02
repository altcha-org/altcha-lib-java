package org.altcha.altcha.v2;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
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
    public void testCanonicalJsonStringEscapingLikeJs() {
        // Expected: JSON.stringify (node); U+007F and U+2028 stay raw
        assertEquals("{\"s\":\"hello\\\"world\\nbreak\\ttab\\\\\\u0001\\u001f\u007f\u2028\\b\\f\\r\"}",
                canonicalData(Map.of("s", "hello\"world\nbreak\ttab\\\u0001\u001f\u007f\u2028\b\f\r")));
    }

    @ParameterizedTest
    @CsvSource({
            // Java double literal, JSON.stringify output (node)
            "1.0,                     1",
            "1.5,                     1.5",
            "-0.0,                    0",
            "1e20,                    100000000000000000000",
            "1e21,                    1e+21",
            "1e-6,                    0.000001",
            "1e-7,                    1e-7",
            "-1.234e-6,               -0.000001234",
            "0.30000000000000004,     0.30000000000000004",
            "8.41e21,                 8.41e+21",       // Double.toString before JDK 19: 8.409999999999999E21
            "5e-324,                  5e-324",
            "1.7976931348623157e308,  1.7976931348623157e+308",
            "NaN,                     null",
            "Infinity,                null",
    })
    public void testJsNumberMatchesJsonStringify(String javaValue, String expected) {
        assertEquals(expected, Altcha.jsNumber(Double.parseDouble(javaValue)));
    }

    @Test
    public void testJsNumberUnsafeIntegersRoundLikeJs() {
        // JS numbers are doubles: 2^53 + 1 is not representable and serialises as 2^53.
        assertEquals("9007199254740991", Altcha.jsNumber(9007199254740991L));
        assertEquals("9007199254740992", Altcha.jsNumber(9007199254740993L));
        assertEquals("12345678901234567000", Altcha.jsNumber(new java.math.BigInteger("12345678901234567890")));
    }

    @Test
    public void testCanonicalJsonDataNumbersAndArrays() {
        var data = new LinkedHashMap<String, Object>();
        data.put("d", 1.0);
        data.put("big", 1e21);
        data.put("list", java.util.List.of(2.5, "x", true));
        var params = new Altcha.ChallengeParameters(
                "SHA-256", "n", "s", 100, 32, "00",
                null, null, null, null, data);
        assertTrue(Altcha.canonicalJson(params).contains(
                "\"data\":{\"big\":1e+21,\"d\":1,\"list\":[2.5,\"x\",true]}"));
    }

    private static String canonicalData(Map<String, Object> data) {
        var json = Altcha.canonicalJson(new Altcha.ChallengeParameters(
                "SHA-256", "n", "s", 100, 32, "00", null, null, null, null, data));
        return json.substring(json.indexOf("\"data\":") + 7, json.indexOf(",\"keyLength\""));
    }

    @Test
    public void testCanonicalJsonArrayIndexKeysFirstLikeJs() {
        var data = new HashMap<String, Object>();
        for (var key : new String[]{"b", "10", "2", "a", "01", "-1", "1.5", "4294967294", "4294967295", "B"}) {
            data.put(key, 1);
        }
        // Expected: altcha-lib canonicalJSON (array indices < 2^32 - 1 first, numerically; then sorted)
        assertEquals("{\"2\":1,\"10\":1,\"4294967294\":1,\"-1\":1,\"01\":1,\"1.5\":1,\"4294967295\":1,"
                + "\"B\":1,\"a\":1,\"b\":1}", canonicalData(data));
    }

    @Test
    public void testCanonicalJsonObjectsInsideArraysKeepInsertionOrderLikeJs() {
        var inArray = new LinkedHashMap<String, Object>();
        inArray.put("z", 1);
        inArray.put("y", Map.of("b", 1));
        inArray.put("3", "three");
        var inner = new HashMap<String, Object>();
        inner.put("d", null);
        inner.put("c", 1e-7);
        var data = new HashMap<String, Object>();
        data.put("b", "x");
        data.put("a", List.of(inArray, "lone\uD800", "pair\uD83D\uDE00"));
        data.put("nested", Map.of("y", 1, "x", inner));
        // Expected: altcha-lib canonicalJSON (sortKeys does not descend into arrays;
        // JSON.stringify escapes lone surrogates)
        assertEquals("{\"a\":[{\"3\":\"three\",\"z\":1,\"y\":{\"b\":1}},\"lone\\ud800\",\"pair\uD83D\uDE00\"],"
                + "\"b\":\"x\",\"nested\":{\"x\":{\"c\":1e-7,\"d\":null},\"y\":1}}", canonicalData(data));
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

    @Test
    public void testSolveChallengeStringCounterModeMatchesReference() throws Exception {
        // altcha-lib v2 solveChallenge({counterMode: 'string'}) on the same parameters: counter 75 (uint32: 659)
        var solution = Altcha.solveChallenge(fixedShaChallenge("00"), Altcha.kdf("SHA-256"), 0, 1,
                Altcha.DEFAULT_SOLVE_TIMEOUT, Altcha.CounterMode.STRING);

        assertEquals(75, solution.counter());
        assertEquals("00d2a8712179b4a90049aaf61cc3af55c37bfba5856d436604b11f053245f131", solution.derivedKey());
    }

    @Test
    public void testCreateChallengeMergesKdfParametersAndUsesCounterMode() throws Exception {
        var sha = Altcha.kdf("SHA-256");
        Altcha.KeyDerivationFunction merging = (p, salt, password) -> new Altcha.DeriveKeyResult(
                sha.deriveKey(p, salt, password).derivedKey(),
                new Altcha.ChallengeParameters(p.algorithm(), p.nonce(), p.salt(), p.cost(), p.keyLength(),
                        p.keyPrefix(), p.keySignature(), 1024, 2, p.expiresAt(), p.data()));
        var challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(1)
                .counter(7)
                .counterMode(Altcha.CounterMode.STRING)
                .deriveKey(merging)
                .hmacSignatureSecret(HMAC_SECRET)
                .hmacKeySignatureSecret("key-signing-secret"));

        assertEquals(1024, challenge.parameters().memoryCost());
        assertEquals(2, challenge.parameters().parallelism());
        var solution = Altcha.solveChallenge(challenge, sha, 0, 1, null, Altcha.CounterMode.STRING);
        assertEquals(7, solution.counter());
        // Merged parameters are signed; both verify paths accept the solution.
        assertTrue(Altcha.verifySolution(challenge, solution, HMAC_SECRET, null, null,
                Altcha.CounterMode.STRING, sha).verified());
        assertTrue(Altcha.verifySolution(challenge, solution, HMAC_SECRET, "key-signing-secret", sha).verified());
    }

    @Test
    public void testVerifyJsCreatedStringModeChallengeWithMergedParameters() throws Exception {
        // Created with altcha-lib (JS) v2: createChallenge({algorithm: 'SHA-256', cost: 1, counter: 7,
        // counterMode: 'string', hmacSignatureSecret: HMAC_SECRET, deriveKey: sha.deriveKey wrapped to return
        // parameters {memoryCost: 1024, parallelism: 2}}), then solveChallenge({counterMode: 'string'}).
        var payload = "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY29zdCI6MSwia2V5TGVuZ3RoIjozMiwia2V5UHJlZml4IjoiNDExYjA3MGRmZDdmNjQzYzlkZTQwYmFiYzgyYTMzYWIiLCJtZW1vcnlDb3N0IjoxMDI0LCJub25jZSI6ImEwZWUyZjRkMjk1NTkzYTdjMzY1YTU2YjhkODFkNmEyIiwicGFyYWxsZWxpc20iOjIsInNhbHQiOiI4NGQwMzQ5ZDA0ZWFlMWVjYjBlYmJmYTQ4NWE3M2I1MiJ9LCJzaWduYXR1cmUiOiJkOTg3OTE5YjU2MzhiMTk5ZTljMDU1ZDg3MTJhMmQxMDY4MzZiZjQ3N2ZjMDQ1NTVlM2E2NTc1NmViYmRlNDUwIn0sInNvbHV0aW9uIjp7ImNvdW50ZXIiOjcsImRlcml2ZWRLZXkiOiI0MTFiMDcwZGZkN2Y2NDNjOWRlNDBiYWJjODJhMzNhYmYwNTkyNGRlOGRkYjM4ZDY4MGJmODI0YWY0ZGQ3NjkxIiwidGltZSI6MH19";
        var p   = Altcha.parsePayload(payload);
        var kdf = Altcha.kdf("SHA-256");

        var stringMode = Altcha.verifySolution(p.challenge(), p.solution(), HMAC_SECRET, null, null,
                Altcha.CounterMode.STRING, kdf);
        var uint32Mode = Altcha.verifySolution(p.challenge(), p.solution(), HMAC_SECRET, kdf);

        assertTrue(stringMode.verified());
        assertFalse(uint32Mode.verified());   // same as JS without counterMode: 'string'
        assertTrue(uint32Mode.invalidSolution());
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

    @ParameterizedTest
    @CsvSource({
            // keyPrefix, expected counter, expected derived key (from the JS reference, altcha-lib v2)
            "a,   20, a1ec80b3",
            "f2e, 42, f2e25aab6d5e504747ad0f52b1ce42afd99d8014634f263ea42b206300037acf",
            "f2,  42, f2e25aab6d5e504747ad0f52b1ce42afd99d8014634f263ea42b206300037acf",
            "F2,  42, f2e25aab6d5e504747ad0f52b1ce42afd99d8014634f263ea42b206300037acf",  // even: bytes, case-insensitive
    })
    public void testSolveChallengeKeyPrefixMatchesReference(String keyPrefix, int expectedCounter,
            String expectedKey) throws Exception {
        var params = new Altcha.ChallengeParameters(
                "PBKDF2/SHA-256", "aabbccdd00112233aabbccdd00112233", "11223344556677889900aabbccddeeff",
                1000, 32, keyPrefix, null, null, null, null, null);
        var challenge = Altcha.signChallenge(Altcha.DEFAULT_HMAC_ALGORITHM, params, null, HMAC_SECRET, null);
        var kdf       = Altcha.kdf("PBKDF2/SHA-256");

        var solution = Altcha.solveChallenge(challenge, kdf);

        assertEquals(expectedCounter, solution.counter());
        assertTrue(solution.derivedKey().startsWith(expectedKey));
        assertTrue(Altcha.verifySolution(challenge, solution, HMAC_SECRET, kdf).verified());
    }

    @Test
    public void testShaKdfKeyLengthBeyondDigestIsTruncatedLikeJs() throws Exception {
        var params = new Altcha.ChallengeParameters(
                "SHA-256", "n", "s", 3, 64, "00", null, null, null, null, null);
        var salt     = HexFormat.of().parseHex("11223344556677889900aabbccddeeff");
        var password = HexFormat.of().parseHex("aabbccdd00112233aabbccdd0011223300000005");

        var derived = Altcha.sha().deriveKey(params, salt, password).derivedKey();

        // altcha-lib sha.deriveKey: derivedKey.subarray(0, 64) of a 32-byte digest
        assertEquals("544847ebea6cd9d17f15875b59a7040f84d4d149ec3771f2c5bd6c9b95fd4c9e",
                HexFormat.of().formatHex(derived));
    }

    @Test
    @Timeout(10)
    public void testKeyPrefixLengthBeyondKeyLengthIsTruncatedLikeJs() throws Exception {
        var challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .counter(5)
                .keyLength(32)
                .keyPrefixLength(40)
                .hmacSignatureSecret(HMAC_SECRET));
        var kdf       = Altcha.kdf("SHA-256");

        assertEquals(64, challenge.parameters().keyPrefix().length());  // whole key, no zero padding
        var solution = Altcha.solveChallenge(challenge, kdf);
        assertEquals(5, solution.counter());
        assertEquals(challenge.parameters().keyPrefix(), solution.derivedKey());
        assertTrue(Altcha.verifySolution(challenge, solution, HMAC_SECRET, kdf).verified());
    }

    private static Altcha.Challenge fixedShaChallenge(String keyPrefix) throws Exception {
        return new Altcha.Challenge(new Altcha.ChallengeParameters(
                "SHA-256", "aabbccdd00112233aabbccdd00112233", "11223344556677889900aabbccddeeff",
                1, 32, keyPrefix, null, null, null, null, null), null);
    }

    @Test
    @Timeout(10)
    public void testSolveChallengeReturnsNullOnTimeout() throws Exception {
        var unsolvable = fixedShaChallenge("00".repeat(32));
        var t0         = System.nanoTime();

        var solution = Altcha.solveChallenge(unsolvable, Altcha.kdf("SHA-256"), 0, 1, Duration.ofMillis(200));

        assertNull(solution);
        assertTrue(Duration.ofNanos(System.nanoTime() - t0).toMillis() >= 200);
    }

    @Test
    @Timeout(10)
    public void testSolveChallengeAbortsOnInterrupt() throws Exception {
        var unsolvable = fixedShaChallenge("00".repeat(32));
        try {
            Thread.currentThread().interrupt();
            assertThrows(InterruptedException.class,
                    () -> Altcha.solveChallenge(unsolvable, Altcha.kdf("SHA-256"), 0, 1, null));
            assertFalse(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    @ParameterizedTest
    @CsvSource({
            // counterStart, expected counter, expected derived key (altcha-lib v2 solveChallenge)
            "2147483647, 2147483658, 001ac71a8b052c3864e44beea41b16d6d2303a15a87b597f12cb6a4cb3048c57",
            "4294967290, 4294967359, 0715bcc59816aac52700c766a481fe48044539f64bed473f9853d585cdaa871e",
    })
    public void testSolveChallengeCounterBeyondInt32MatchesReference(long counterStart, long expectedCounter,
            String expectedKey) throws Exception {
        var solution = Altcha.solveChallenge(fixedShaChallenge("0"), Altcha.kdf("SHA-256"), counterStart, 1);

        assertEquals(expectedCounter, solution.counter());
        assertEquals(expectedKey, solution.derivedKey());
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
    public void testVerifySolutionExpiredWithinCurrentSecond() throws Exception {
        // Move at least 100 ms into the current second, then expire at its start: already in the past.
        Thread.sleep(Math.max(0, 100 - System.currentTimeMillis() % 1000));
        var expiresAt = System.currentTimeMillis() / 1000;
        var challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .expiresAt(expiresAt)
                .hmacSignatureSecret(HMAC_SECRET));
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, kdf);

        assertFalse(result.verified());
        assertTrue(result.expired());
    }

    @Test
    public void testVerifySolutionExpiresAtZeroMeansNoExpiry() throws Exception {
        // JS: `expiresAt && …` — 0 is falsy, so the expiry check is skipped.
        var challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .expiresAt(0L)
                .hmacSignatureSecret(HMAC_SECRET));
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, kdf);

        assertTrue(result.verified());
        assertFalse(result.expired());
    }

    @Test
    public void testVerifyJsCreatedChallengeWithExpiresAtZero() throws Exception {
        // Created and solved with altcha-lib (JS) v2: createChallenge({algorithm: 'SHA-256', cost: 1,
        // hmacSignatureSecret: HMAC_SECRET, expiresAt: 0}), then solveChallenge. JS verifies it.
        var payload = "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY29zdCI6MSwiZXhwaXJlc0F0IjowLCJrZXlMZW5ndGgiOjMyLCJrZXlQcmVmaXgiOiIwMCIsIm5vbmNlIjoiYWRmNzc3ZGRhZjUzYTkwYjAwOGFlNTE4OWQ1ZjM0Y2MiLCJzYWx0IjoiMmY2ZTg0NzMzZWJhYmU1ODMxYWRkMDRmM2VjOTEwMzcifSwic2lnbmF0dXJlIjoiY2YxMTgzMDg3NzBiZWM5ZWIzZTZlNmVlNGM1Zjk3OWU2NjFkYzcwNGFjNjY4YjA2ZjA2MTY5ZjVkMmMxZDliYyJ9LCJzb2x1dGlvbiI6eyJjb3VudGVyIjoxMTI1LCJkZXJpdmVkS2V5IjoiMDBjMmEzOTc5MGIyYzdjOGUzODY5NTkyMWE1MmIzOWM3YzBlOGJhMzVhODliYWVlYWIxZjBlNWFiOTMzNmI4OSIsInRpbWUiOjAuOH19";

        var result = Altcha.verifySolution(payload, HMAC_SECRET, Altcha.kdf("SHA-256"));

        assertTrue(result.verified());
        assertFalse(result.expired());
    }

    @ParameterizedTest
    @CsvSource({
            // altcha-lib (JS) v2: createChallenge({algorithm: 'SHA-256', cost: 1, hmacSignatureSecret: HMAC_SECRET,
            // expiresAt}), then solveChallenge. JS result: 4102444800.5 → verified; 1.5 → expired.
            "4102444800.5, false, eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY29zdCI6MSwiZXhwaXJlc0F0Ijo0MTAyNDQ0ODAwLjUsImtleUxlbmd0aCI6MzIsImtleVByZWZpeCI6IjAwIiwibm9uY2UiOiI4MjA1NjJmYzYwYTY0NWZjMzZiNjE5NDI5YWM3N2E0OCIsInNhbHQiOiI1ZTA0M2E1ZjJlZGJjMDAxZWUxNWI5YmEyMjYzYWIyYiJ9LCJzaWduYXR1cmUiOiI3YmQ4MDZhNTdmNzg5YTRkNjNjOWIxODNkNTM2MTFiYWFjZGU5MDJkMjliYjdlOGQ5ZTFmOThhNzg5NDJjNjY2In0sInNvbHV0aW9uIjp7ImNvdW50ZXIiOjIzMCwiZGVyaXZlZEtleSI6IjAwYjIxZmMyNmM0YmEwNjEzZWQyMzI3Y2RlOTAzOGJiNTIxMjM5MmYzM2NjNmIyMTgzYzQyZGIzM2RiODE0NzAiLCJ0aW1lIjowLjF9fQ==",
            "1.5,          true,  eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY29zdCI6MSwiZXhwaXJlc0F0IjoxLjUsImtleUxlbmd0aCI6MzIsImtleVByZWZpeCI6IjAwIiwibm9uY2UiOiJmNThlYmFlMTUyZDM3ZGNmZWZkMWMyYWM0NDhjNzBjMSIsInNhbHQiOiIxODM2MDgwOGVhZDdmMjE3MDQ2YjIyMzEyNzk4NDJhMCJ9LCJzaWduYXR1cmUiOiIzZTJhOTNiNmEzYjhlNDQwZmM3Njk0NGU2MTM2YzZmOGEzZDJjNTE1YzM2MDg1NDliZTRjNDkzNzlmOWNmMzgzIn0sInNvbHV0aW9uIjp7ImNvdW50ZXIiOjU5MCwiZGVyaXZlZEtleSI6IjAwNDQ4ZWI4MTY3MWY3NmYwNzRiNzZjZjc2MGVlYjI1ZGZkNTBlM2QyOTUxZDYxMDBmNjRlY2EwOTI4YzkzZmQiLCJ0aW1lIjoxLjR9fQ==",
    })
    public void testVerifyJsCreatedChallengeWithFractionalExpiresAt(double expiresAt, boolean expired,
            String payload) throws Exception {
        assertEquals(expiresAt, Altcha.parsePayload(payload).challenge().parameters().expiresAt());

        var result = Altcha.verifySolution(payload, HMAC_SECRET, Altcha.kdf("SHA-256"));

        assertEquals(expired, result.expired());
        assertEquals(!expired, result.verified());   // signature over the fractional value must match
    }

    @Test
    public void testVerifyJsCreatedChallengeWithCounterBeyondInt32() throws Exception {
        // Created with altcha-lib (JS) v2: createChallenge({algorithm: 'SHA-256', cost: 1, keyPrefix: '0',
        // hmacSignatureSecret: HMAC_SECRET}), then solveChallenge({counterStart: 3_000_000_000}) → counter 3000000004.
        var payload = "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY29zdCI6MSwia2V5TGVuZ3RoIjozMiwia2V5UHJlZml4IjoiMCIsIm5vbmNlIjoiOGZkMTA4MTUxYzdhNmY5OTY3OGQyODc2Yjc0OGYxMTMiLCJzYWx0IjoiZWJkZWQxOTlhNjA2YTViMjU1MmZjOGUwODc3ZTU1NzQifSwic2lnbmF0dXJlIjoiY2JkM2M3ZTIxMzQ2Mjk2YjEyZWZhNDU2MzJlZGJkNDQxN2I3MzI3OTcyOWUwYzJlZDBjZjMwNjM0ZWM2MzNkMyJ9LCJzb2x1dGlvbiI6eyJjb3VudGVyIjozMDAwMDAwMDA0LCJkZXJpdmVkS2V5IjoiMDMyYmRlMWVjNjA3ZWI4MjNhMGUwYTA1ZWQ4YjFlZWQxOTExOTRkMDE4MTU2Y2I2YzNmZTJhYmRmMDUyMTBiMCIsInRpbWUiOjB9fQ==";

        var payloadObj = Altcha.parsePayload(payload);
        var result     = Altcha.verifySolution(payload, HMAC_SECRET, Altcha.kdf("SHA-256"));

        assertEquals(3_000_000_004L, payloadObj.solution().counter());
        assertTrue(result.verified());
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
    public void testVerifySolutionNullDerivedKey() throws Exception {
        var challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .hmacSignatureSecret(HMAC_SECRET));
        var solution  = new Altcha.Solution(0, null, null);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, Altcha.kdf("SHA-256"));

        assertFalse(result.verified());
        assertFalse(result.invalidSignature());
        assertTrue(result.invalidSolution());
    }

    @Test
    public void testVerifySolutionSlowPathRejectsWrongKeyPrefix() throws Exception {
        // Regression test: the slow (re-derive) path must reject a solution whose
        // derived key does not satisfy the signed keyPrefix, even when the derived
        // key itself matches what re-deriving with the submitted counter produces.
        // Without this check an attacker could submit counter=0 with its real
        // (unbruteforced) derived key and bypass the proof-of-work entirely.
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .counter(0)
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf("SHA-256");
        // counter=0 trivially satisfies its own (matching) keyPrefix here.
        var solution  = Altcha.solveChallenge(challenge, kdf, 0, 1);
        assertEquals(0, solution.counter());

        // Tamper the (still validly-signed) challenge so the required prefix no
        // longer matches the derived key the attacker already has in hand.
        var realPrefix    = challenge.parameters().keyPrefix();
        var invertedFirst = (~Integer.parseInt(realPrefix.substring(0, 2), 16)) & 0xff;
        var wrongPrefix    = String.format("%02x", invertedFirst) + realPrefix.substring(2);
        var tamperedParams = challenge.parameters().withKeyPrefix(wrongPrefix);
        var tamperedChallenge = Altcha.signChallenge(
                Altcha.DEFAULT_HMAC_ALGORITHM, tamperedParams, null, HMAC_SECRET, null);

        var result = Altcha.verifySolution(tamperedChallenge, solution, HMAC_SECRET, kdf);

        assertFalse(result.verified());
        assertFalse(result.expired());
        assertFalse(result.invalidSignature());
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

    @ParameterizedTest
    @ValueSource(strings = {"SHA-384", "SHA-512"})
    public void testVerifySolutionHonoursHmacAlgorithm(String hmacAlgorithm) throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .hmacAlgorithm(hmacAlgorithm)
                .hmacSignatureSecret(HMAC_SECRET);
        var challenge = Altcha.createChallenge(opts);
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, null, hmacAlgorithm, kdf);
        assertTrue(result.verified());

        // Verifying with the default (SHA-256) must not accept a challenge signed with another algorithm
        var mismatched = Altcha.verifySolution(challenge, solution, HMAC_SECRET, kdf);
        assertFalse(mismatched.verified());
        assertTrue(mismatched.invalidSignature());

        // Same through the base64 entry point
        var json   = "{\"challenge\":" + challenge.toJson() + ",\"solution\":{\"counter\":" + solution.counter()
                + ",\"derivedKey\":\"" + solution.derivedKey() + "\"}}";
        var base64 = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        assertTrue(Altcha.verifySolution(base64, HMAC_SECRET, null, hmacAlgorithm, null, kdf).verified());
        assertTrue(Altcha.verifySolution(base64, HMAC_SECRET, kdf).invalidSignature());
    }

    @ParameterizedTest
    @ValueSource(strings = {"SHA-384", "SHA-512"})
    public void testVerifySolutionKeySignatureHonoursHmacAlgorithm(String hmacAlgorithm) throws Exception {
        var opts = new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .counter(5)
                .hmacAlgorithm(hmacAlgorithm)
                .hmacSignatureSecret(HMAC_SECRET)
                .hmacKeySignatureSecret("key-signing-secret");
        var challenge = Altcha.createChallenge(opts);
        var solution  = Altcha.solveChallenge(challenge, Altcha.kdf("SHA-256"));

        // No KDF: must succeed via the keySignature path
        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET,
                "key-signing-secret", hmacAlgorithm, null);
        assertTrue(result.verified());

        var forged = new Altcha.Solution(solution.counter(), "00".repeat(32), null);
        var rejected = Altcha.verifySolution(challenge, forged, HMAC_SECRET,
                "key-signing-secret", hmacAlgorithm, null);
        assertFalse(rejected.verified());
        assertTrue(rejected.invalidSolution());
    }

    private static Altcha.Challenge createKeySignatureChallenge() throws Exception {
        return Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .counter(5)
                .hmacSignatureSecret(HMAC_SECRET)
                .hmacKeySignatureSecret("key-signing-secret"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"abc", "zz", "0g", "\u0660\u0660"})  // odd length, non-hex, non-ASCII digits
    public void testVerifySolutionKeySignatureRejectsMalformedDerivedKey(String derivedKey) throws Exception {
        var challenge = createKeySignatureChallenge();
        var solution  = new Altcha.Solution(5, derivedKey, null);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, "key-signing-secret", null);

        assertFalse(result.verified());
        assertFalse(result.invalidSignature());
        assertTrue(result.invalidSolution());
    }

    @Test
    public void testVerifySolutionKeySignatureAcceptsUppercaseDerivedKey() throws Exception {
        // JS hexToBuffer is case-insensitive, so an uppercase hex key is the same key.
        var challenge = createKeySignatureChallenge();
        var solution  = Altcha.solveChallenge(challenge, Altcha.kdf("SHA-256"));
        var upper     = new Altcha.Solution(solution.counter(), solution.derivedKey().toUpperCase(), null);

        var result = Altcha.verifySolution(challenge, upper, HMAC_SECRET, "key-signing-secret", null);

        assertTrue(result.verified());
    }

    @Test
    public void testVerifySolutionBase64WithKeySignatureSecretUsesFastPath() throws Exception {
        var challenge = createKeySignatureChallenge();
        var solution  = Altcha.solveChallenge(challenge, Altcha.kdf("SHA-256"));
        var json      = "{\"challenge\":" + challenge.toJson() + ",\"solution\":{\"counter\":" + solution.counter()
                + ",\"derivedKey\":\"" + solution.derivedKey() + "\",\"time\":0.8}}";
        var base64    = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));

        // No KDF: only the keySignature path can verify it.
        var result = Altcha.verifySolution(base64, HMAC_SECRET, "key-signing-secret", null);

        assertTrue(result.verified());
        assertEquals(0.8, Altcha.parsePayload(base64).solution().time());
    }

    @Test
    public void testVerifySolutionResultJsonMatchesJsShape() {
        // JS always emits invalidSignature/invalidSolution (null when unset); time is a float in ms.
        assertEquals("{\"expired\":true,\"invalidSignature\":null,\"invalidSolution\":null,\"time\":0.3,\"verified\":false}",
                new Altcha.VerifySolutionResult(false, true, null, null, 0.3).toJson());
        assertEquals("{\"expired\":false,\"invalidSignature\":false,\"invalidSolution\":false,\"time\":12,\"verified\":true}",
                new Altcha.VerifySolutionResult(true, false, false, false, 12.0).toJson());
    }

    @Test
    public void testHmacAlgorithmNamesFollowWebCrypto() throws Exception {
        var challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .hmacAlgorithm("sha-384")
                .hmacSignatureSecret(HMAC_SECRET));
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        // WebCrypto names are case-insensitive...
        assertTrue(Altcha.verifySolution(challenge, solution, HMAC_SECRET, null, "SHA-384", kdf).verified());
        // ...and anything else is rejected instead of silently using SHA-256.
        for (var unsupported : new String[]{"SHA256", "MD5", ""}) {
            assertThrows(IllegalArgumentException.class,
                    () -> Altcha.verifySolution(challenge, solution, HMAC_SECRET, null, unsupported, kdf));
        }
    }

    @Test
    public void testCreateChallengeEmptySignatureSecretIsUnsigned() throws Exception {
        var challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .hmacSignatureSecret(""));

        assertNull(challenge.signature());
    }

    @Test
    public void testEmptyKeySignatureSecretSkipsKeySignature() throws Exception {
        var challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .counter(5)
                .hmacSignatureSecret(HMAC_SECRET)
                .hmacKeySignatureSecret(""));
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        assertNotNull(challenge.signature());
        assertNull(challenge.parameters().keySignature());
        assertTrue(Altcha.verifySolution(challenge, solution, HMAC_SECRET, "", kdf).verified());
    }

    @Test
    public void testVerifySolutionEmptyKeySecretFallsBackToRederive() throws Exception {
        var challenge = createKeySignatureChallenge();
        var kdf       = Altcha.kdf("SHA-256");
        var solution  = Altcha.solveChallenge(challenge, kdf);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, "", kdf);

        assertTrue(result.verified());
    }

    @Test
    public void testVerifySolutionEmptyKeySignatureFallsBackToRederive() throws Exception {
        var kdf       = Altcha.kdf("SHA-256");
        var unsigned  = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .counter(5));
        var challenge = Altcha.signChallenge(Altcha.DEFAULT_HMAC_ALGORITHM,
                unsigned.parameters().withKeySignature(""), null, HMAC_SECRET, null);
        var solution  = Altcha.solveChallenge(challenge, kdf);

        var result = Altcha.verifySolution(challenge, solution, HMAC_SECRET, "key-signing-secret", kdf);

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

    @Test
    public void testVerifyJsCreatedChallengeWithNumericData() throws Exception {
        // Created and solved with altcha-lib (JS) v2: createChallenge({algorithm: 'SHA-256', cost: 1,
        // hmacSignatureSecret: HMAC_SECRET, data: {big: 1e21, small: 1e-7, frac: 1.5, one: 1.0,
        // neg: -0.000001234, sum: 0.1 + 0.2}}), then solveChallenge.
        var payload = "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY29zdCI6MSwiZGF0YSI6eyJiaWciOjFlKzIxLCJmcmFjIjoxLjUsIm5lZyI6LTAuMDAwMDAxMjM0LCJvbmUiOjEsInNtYWxsIjoxZS03LCJzdW0iOjAuMzAwMDAwMDAwMDAwMDAwMDR9LCJrZXlMZW5ndGgiOjMyLCJrZXlQcmVmaXgiOiIwMCIsIm5vbmNlIjoiOTg0ZDdmMDJlNTMzZDhmOWE0N2ZhNzlmNjQxY2I1MzciLCJzYWx0IjoiYTNlNGMwZmEzNGEyYmNjNzU0MmU0Yjk1ZTNiMzYyODYifSwic2lnbmF0dXJlIjoiNmIxYTUxMGUyMjJjZTg4Yjc1YjkxOGU3YzUwNWM3N2Q5ZGY3NDVjYTQxMTYzYmIzMDEwMGFmOWZjOWJkYjE4ZCJ9LCJzb2x1dGlvbiI6eyJjb3VudGVyIjoyMDYsImRlcml2ZWRLZXkiOiIwMDc2ZDM4OTNjMjI0OGEyNDMyYzJjMjFjMzMwYmUxODE1MGM5NGIyMTJhNTEyM2E2NDA3MTJhMGFkNDUzNTYwIiwidGltZSI6MC44fX0=";

        var result = Altcha.verifySolution(payload, HMAC_SECRET, Altcha.kdf("SHA-256"));

        assertFalse(result.invalidSignature());
        assertTrue(result.verified());
    }

    @Test
    public void testVerifyJavaChallengeWithDoubleDataAfterJsonRoundTrip() throws Exception {
        // The widget parses challenge.toJson() and sends the parameters back re-serialised.
        var challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
                .algorithm("SHA-256")
                .cost(10)
                .hmacSignatureSecret(HMAC_SECRET)
                .data(Map.of("one", 1.0, "small", 1e-7, "big", 1e21)));
        var kdf      = Altcha.kdf("SHA-256");
        var solution = Altcha.solveChallenge(challenge, kdf);
        var json     = "{\"challenge\":" + challenge.toJson()
                + ",\"solution\":{\"counter\":" + solution.counter()
                + ",\"derivedKey\":\"" + solution.derivedKey() + "\"}}";
        var base64   = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));

        var result = Altcha.verifySolution(base64, HMAC_SECRET, kdf);

        assertFalse(result.invalidSignature());
        assertTrue(result.verified());
    }

    @Test
    public void testVerifyJsCreatedChallengeWithNestedData() throws Exception {
        // Created and solved with altcha-lib (JS) v2: createChallenge({algorithm: 'SHA-256', cost: 1,
        // hmacSignatureSecret: HMAC_SECRET, data: {b: 'x', 10: 1, 2: 'two',
        // a: [{z: 1, y: 2, 3: 'three'}, 'lone\uD800'], nested: {y: 1, x: {d: null, c: 1e-7}}}}), then solveChallenge.
        var payload = "eyJjaGFsbGVuZ2UiOnsicGFyYW1ldGVycyI6eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY29zdCI6MSwiZGF0YSI6eyIyIjoidHdvIiwiMTAiOjEsImEiOlt7IjMiOiJ0aHJlZSIsInoiOjEsInkiOjJ9LCJsb25lXHVkODAwIl0sImIiOiJ4IiwibmVzdGVkIjp7IngiOnsiYyI6MWUtNywiZCI6bnVsbH0sInkiOjF9fSwia2V5TGVuZ3RoIjozMiwia2V5UHJlZml4IjoiMDAiLCJub25jZSI6IjBkNTkxNzI1YjU4NWNiYzAyNTVkNjNlNDAyN2IxNDc4Iiwic2FsdCI6IjBiNTA1ODlkMTRlMDk2MDI1OWQ2NjU5ZGRkYjFmOGY4In0sInNpZ25hdHVyZSI6ImMxZjQ4MTdmNWJmYmQ1ZWU5MmU5YTg1MzA2OWZlOWFhYzUyNmEwYWE0ZGQ2MWExYmI1Y2I3N2U4Y2IwZGY4OWIifSwic29sdXRpb24iOnsiY291bnRlciI6MTE0LCJkZXJpdmVkS2V5IjoiMDA1YzE1OTFjMGE0YWQ0ZjMzYjNiMzBmNWEzYmE4YjRmNmY2YTMyNjZkZmFiYjE3YTVkMTU1ZTRiYzdmMmUzNSIsInRpbWUiOjAuMX19";

        var result = Altcha.verifySolution(payload, HMAC_SECRET, Altcha.kdf("SHA-256"));

        assertFalse(result.invalidSignature());
        assertTrue(result.verified());
    }

    @Test
    public void testParsePayloadWithNullOptionalParams() throws Exception {
        // Payload with optional fields as null
        var algorithm    = "PBKDF2/SHA-256";
        var nonce        = "35e76d0bf62dbacfb6e571185f6e1ce1";
        var salt         = "b91ec8659c07572037329ef67ce1c0a5";
        var cost         = 5000;
        var keyLength    = 32;
        var keyPrefix    = "048ab54265fd06ff21089afead7e73ff";
        var keySignature = "null"; // optional — null
        var memoryCost   = "null"; // optional — null
        var parallelism  = "null"; // optional — null
        var expiresAt    = "null"; // optional — null
        var data         = "null"; // optional — null
        var signature    = "null"; // optional - null
        var counter      = 5000;
        var derivedKey   = "048ab54265fd06ff21089afead7e73ffa7afe5cc448ac51b92bf66b86f6e350e";
        var time         = "null"; // optional — null

        var json = String.format(
                "{\"challenge\":{\"parameters\":{\"algorithm\":\"%s\",\"nonce\":\"%s\"," +
                "\"salt\":\"%s\",\"cost\":%d,\"keyLength\":%d,\"keyPrefix\":\"%s\"," +
                "\"keySignature\":%s,\"memoryCost\":%s,\"parallelism\":%s," +
                "\"expiresAt\":%s,\"data\":%s},\"signature\":\"%s\"}," +
                "\"solution\":{\"counter\":%d,\"derivedKey\":\"%s\",\"time\":%s}}",
                algorithm, nonce, salt, cost, keyLength, keyPrefix,
                keySignature, memoryCost, parallelism, expiresAt, data, signature,
                counter, derivedKey, time);
        var base64 = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));

        var payload = Altcha.parsePayload(base64);
        assertNull(payload.challenge().parameters().keySignature());
        assertNull(payload.challenge().parameters().memoryCost());
        assertNull(payload.challenge().parameters().parallelism());
        assertNull(payload.challenge().parameters().expiresAt());
        assertNull(payload.challenge().parameters().data());
        assertNull(payload.solution().time());
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
        var payload = signedServerPayload("score=0.9&verified=true&location.countryCode=DE");
        var result  = Altcha.verifyServerSignature(payload, HMAC_SECRET);

        assertTrue(result.verified());
        assertEquals("DE", result.verificationData().get("location.countryCode"));
        assertEquals(0.9, result.verificationData().score().doubleValue());
    }

    @Test
    public void testParseSentinelVerificationDataLikeJs() {
        // Real verificationData from ALTCHA Sentinel; expected: altcha-lib parseVerificationData + JSON.stringify
        var data = Altcha.parseVerificationData("location.countryCode=id&location.score=0&location.timeZone=Asia%2FMakassar"
                + "&location.triggeredRules=&id=1k3tet87i00b0lhjm0j&classification=GOOD&challengeAlgorithm=PBKDF2%2FSHA-256"
                + "&device.browser=Firefox&device.edk=f359ed9ca9c06d6cd4e55cea0e87748a&device.type=desktop&expire=1790917537"
                + "&ipAddress=104.28.215.132&penalty=0&origin=https%3A%2F%2Fplayground.altcha.org&reasons=&score=0"
                + "&time=1790916339&verified=true");

        assertEquals("{\"location.countryCode\":\"id\",\"location.score\":0,\"location.timeZone\":\"Asia/Makassar\","
                + "\"location.triggeredRules\":\"\",\"id\":\"1k3tet87i00b0lhjm0j\",\"classification\":\"GOOD\","
                + "\"challengeAlgorithm\":\"PBKDF2/SHA-256\",\"device.browser\":\"Firefox\","
                + "\"device.edk\":\"f359ed9ca9c06d6cd4e55cea0e87748a\",\"device.type\":\"desktop\",\"expire\":1790917537,"
                + "\"ipAddress\":\"104.28.215.132\",\"penalty\":0,\"origin\":\"https://playground.altcha.org\","
                + "\"reasons\":\"\",\"score\":0,\"time\":1790916339,\"verified\":true}", data.toJson());
        assertEquals(List.of(), data.reasons());
        assertEquals(1790917537L, data.expire());
        assertEquals("GOOD", data.classification());
        assertTrue(data.verified());
    }

    @Test
    public void testParseVerificationDataEdgeCasesLikeJs() {
        var data = Altcha.parseVerificationData("?b=1&b=2&flag&c=%zz%E9&d=+x%20&fields=a,b,&reasons=%20&n=1.50"
                + "&big=123456789012345678901&2=two&t=true&f=FALSE&x=1.&y=.5&&=empty");

        // Expected: altcha-lib parseVerificationData + JSON.stringify (node 24)
        assertEquals("{\"2\":\"two\",\"b\":2,\"flag\":\"\",\"c\":\"%zz\uFFFD\",\"d\":\"x\",\"fields\":[\"a\",\"b\",\"\"],"
                + "\"reasons\":[\"\"],\"n\":1.5,\"big\":123456789012345680000,\"t\":true,\"f\":\"FALSE\","
                + "\"x\":\"1.\",\"y\":\".5\",\"\":\"empty\"}", data.toJson());
        // WHATWG UTF-8 decode: one U+FFFD per invalid byte subsequence (URLSearchParams in node and Bun)
        assertEquals("\uFFFD\uFFFD\uFFFD\uD83D\uDE00\uFFFD\uFFFD\uFFFDx",
                Altcha.parseVerificationData("s=%ED%A0%80%F0%9F%98%80%C3%E0%80x").get("s"));
    }

    @Test
    public void testVerifyServerSignatureResultLikeJs() throws Exception {
        var valid    = signedServerPayload("verified=true&score=0.5");
        var tampered = new Altcha.ServerSignaturePayload("SHA-256", null, null,
                valid.verificationData(), "00".repeat(32), true);
        var notVerified = signedServerPayload("verified=false");

        var bad = Altcha.verifyServerSignature(tampered, HMAC_SECRET);
        assertFalse(bad.verified());
        assertTrue(bad.invalidSignature());
        assertFalse(bad.invalidSolution());
        assertFalse(bad.expired());

        var unverified = Altcha.verifyServerSignature(notVerified, HMAC_SECRET);
        assertFalse(unverified.verified());
        assertFalse(unverified.invalidSignature());
        assertTrue(unverified.invalidSolution());

        // Same keys and order as the JS result: {expired, invalidSignature, invalidSolution, time, verificationData, verified}
        var json = Altcha.verifyServerSignature(valid, HMAC_SECRET).toJson();
        assertTrue(json.matches("\\{\"expired\":false,\"invalidSignature\":false,\"invalidSolution\":false,"
                + "\"time\":[0-9.]+,\"verificationData\":\\{\"verified\":true,\"score\":0\\.5},\"verified\":true}"), json);
    }

    private static Altcha.ServerSignaturePayload signedServerPayload(String verData) throws Exception {
        var md   = java.security.MessageDigest.getInstance("SHA-256");
        var hash = md.digest(verData.getBytes(StandardCharsets.UTF_8));
        var mac  = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(
                HMAC_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        var sig  = Altcha.bytesToHex(mac.doFinal(hash));
        return new Altcha.ServerSignaturePayload("SHA-256", null, null, verData, sig, true);
    }

    @Test
    public void testVerifyServerSignatureExpireLikeJs() throws Exception {
        // Keep the whole test within one wall-clock second.
        var msIntoSecond = System.currentTimeMillis() % 1000;
        if (msIntoSecond > 800) Thread.sleep(1000 - msIntoSecond);
        var now = System.currentTimeMillis() / 1000;

        // JS: expired = !!expire && expire < Math.floor(Date.now() / 1000)
        assertFalse(Altcha.verifyServerSignature(signedServerPayload("verified=true&expire=" + (now - 1)), HMAC_SECRET).verified());
        assertTrue(Altcha.verifyServerSignature(signedServerPayload("verified=true&expire=" + now), HMAC_SECRET).verified());
        assertTrue(Altcha.verifyServerSignature(signedServerPayload("verified=true&expire=" + (now + 60)), HMAC_SECRET).verified());
        assertTrue(Altcha.verifyServerSignature(signedServerPayload("verified=true&expire=0"), HMAC_SECRET).verified());
        // Non-numeric strings are coerced like JS: "-5" → -5 (expired), "abc" → NaN (not expired)
        assertTrue(Altcha.verifyServerSignature(signedServerPayload("verified=true&expire=-5"), HMAC_SECRET).expired());
        assertFalse(Altcha.verifyServerSignature(signedServerPayload("verified=true&expire=abc"), HMAC_SECRET).expired());
    }

    @Test
    public void testVerifyServerSignatureExpireCoercionIsLinear() {
        // Unauthenticated input: these took 16-41 s with a backtracking regex / unbounded BigInteger.
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            assertFalse(Altcha.verifyServerSignature(signedServerPayload("verified=true&expire=" + "1".repeat(100_000) + "x"), HMAC_SECRET).expired());
            // 0x fff…f (1M digits) ≥ 2^1024 → Infinity, like JS Number()
            assertFalse(Altcha.verifyServerSignature(signedServerPayload("verified=true&expire=0x" + "f".repeat(1_000_000)), HMAC_SECRET).expired());
            // Leading zeros don't count towards the size: 0x000…01 == 1 → expired
            assertTrue(Altcha.verifyServerSignature(signedServerPayload("verified=true&expire=0x" + "0".repeat(1_000_000) + "1"), HMAC_SECRET).expired());
        });
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
