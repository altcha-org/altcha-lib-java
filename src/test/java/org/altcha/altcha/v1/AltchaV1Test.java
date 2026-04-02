package org.altcha.altcha.v1;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AltchaV1Test {

    @Test
    public void testRandomBytes() {
        var bytes = Altcha.randomBytes(16);
        assertNotNull(bytes);
        assertEquals(16, bytes.length);
    }

    @Test
    public void testRandomInt() {
        var random = Altcha.randomInt(100);
        assertTrue(random >= 0 && random < 100);
    }

    @Test
    public void testHashHex() throws Exception {
        var hash = Altcha.hashHex(Altcha.Algorithm.SHA256, "hello");
        assertNotNull(hash);
        assertEquals(64, hash.length());
        // Known SHA-256 of "hello"
        assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash);
    }

    @Test
    public void testHmacHex() throws Exception {
        var hmac = Altcha.hmacHex(Altcha.Algorithm.SHA256, "hello".getBytes(StandardCharsets.UTF_8), "secret");
        assertNotNull(hmac);
        assertEquals(64, hmac.length());
    }

    @Test
    public void testCreateChallenge() throws Exception {
        var options = new Altcha.ChallengeOptions().hmacKey("secret");
        var challenge = Altcha.createChallenge(options);

        assertNotNull(challenge);
        assertEquals(Altcha.DEFAULT_ALGORITHM.getName(), challenge.algorithm());
        assertTrue(challenge.maxnumber() > 0);
        assertNotNull(challenge.salt());
        assertNotNull(challenge.signature());
        assertNotNull(challenge.challenge());
        assertTrue(challenge.salt().endsWith("&"), "salt must end with & delimiter");
    }

    @Test
    public void testCreateChallengeWithParams() throws Exception {
        var options = new Altcha.ChallengeOptions()
                .hmacKey("secret")
                .param("userId", "42")
                .expiresInSeconds(300);
        var challenge = Altcha.createChallenge(options);

        assertTrue(challenge.salt().contains("userId=42"), "salt must contain custom param");
        assertTrue(challenge.salt().contains("expires="), "salt must contain expires");
    }

    @Test
    public void testVerifySolution() throws Exception {
        var options = new Altcha.ChallengeOptions()
                .number(100L)
                .hmacKey("secret");
        var challenge = Altcha.createChallenge(options);

        var payload = new Altcha.Payload(
                challenge.algorithm(),
                challenge.challenge(),
                100L,
                challenge.salt(),
                challenge.signature());

        assertTrue(Altcha.verifySolution(payload, "secret", false));
    }

    @Test
    public void testVerifySolutionWrongNumber() throws Exception {
        var options = new Altcha.ChallengeOptions()
                .number(100L)
                .hmacKey("secret");
        var challenge = Altcha.createChallenge(options);

        var payload = new Altcha.Payload(
                challenge.algorithm(),
                challenge.challenge(),
                999L,   // wrong number
                challenge.salt(),
                challenge.signature());

        assertFalse(Altcha.verifySolution(payload, "secret", false));
    }

    @Test
    public void testVerifySolutionSaltSplicing() throws Exception {
        // Ensure that appending bytes to the salt to shift the number doesn't work.
        var options = new Altcha.ChallengeOptions()
                .number(123L)
                .hmacKey("secret");
        var challenge = Altcha.createChallenge(options);

        var payload = new Altcha.Payload(
                challenge.algorithm(),
                challenge.challenge(),
                23L,                           // attacker uses number=23
                challenge.salt() + "1",        // and appends "1" to salt so salt+23 == original_salt+123
                challenge.signature());

        assertFalse(Altcha.verifySolution(payload, "secret", false));
    }

    @Test
    public void testVerifySolutionExpired() throws Exception {
        var options = new Altcha.ChallengeOptions()
                .number(1L)
                .hmacKey("secret")
                .expires(System.currentTimeMillis() / 1000 - 10); // already expired
        var challenge = Altcha.createChallenge(options);

        var payload = new Altcha.Payload(
                challenge.algorithm(),
                challenge.challenge(),
                1L,
                challenge.salt(),
                challenge.signature());

        assertFalse(Altcha.verifySolution(payload, "secret", true));
        assertTrue(Altcha.verifySolution(payload, "secret", false)); // same but without expiry check
    }

    @Test
    public void testVerifySolutionBase64() throws Exception {
        var options = new Altcha.ChallengeOptions()
                .number(5L)
                .hmacKey("secret");
        var challenge = Altcha.createChallenge(options);

        var json = String.format(
                "{\"algorithm\":\"%s\",\"challenge\":\"%s\",\"number\":%d,\"salt\":\"%s\",\"signature\":\"%s\"}",
                challenge.algorithm(), challenge.challenge(), 5, challenge.salt(), challenge.signature());
        var base64 = java.util.Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));

        assertTrue(Altcha.verifySolution(base64, "secret", false));
    }

    @Test
    public void testExtractParams() throws Exception {
        var params = Altcha.extractParams("testSalt?param1=value1&param2=value2");
        assertEquals(2, params.size());
        assertEquals("value1", params.get("param1"));
        assertEquals("value2", params.get("param2"));
    }

    @Test
    public void testExtractParamsNoQuery() throws Exception {
        var params = Altcha.extractParams("justahexsalt&");
        assertTrue(params.isEmpty());
    }

    @Test
    public void testVerifyFieldsHash() throws Exception {
        var formData = Map.of("field1", "value1", "field2", "value2");
        var fields   = new String[]{"field1", "field2"};
        var hash     = Altcha.hashHex(Altcha.Algorithm.SHA256, "value1\nvalue2");

        assertTrue(Altcha.verifyFieldsHash(formData, fields, hash, Altcha.Algorithm.SHA256));
    }

    @Test
    public void testVerifyServerSignature() throws Exception {
        var payload = new Altcha.ServerSignaturePayload(
                Altcha.Algorithm.SHA256,
                null,
                null,
                "score=3&verified=true&location.countryCode=US",
                null, // will compute below
                true);

        var hash = Altcha.hash(Altcha.Algorithm.SHA256,
                payload.verificationData().getBytes(StandardCharsets.UTF_8));
        var sig  = Altcha.hmacHex(Altcha.Algorithm.SHA256, hash, "secret");

        var signed = new Altcha.ServerSignaturePayload(
                payload.algorithm(), payload.apiKey(), payload.id(),
                payload.verificationData(), sig, payload.verified());

        var result = Altcha.verifyServerSignature(signed, "secret");
        assertTrue(result.verified());
        assertEquals("US", result.verificationData().getAdditionalField("location.countryCode"));
    }

    @Test
    public void testSolveChallenge() throws Exception {
        var options  = new Altcha.ChallengeOptions().hmacKey("secret").maxNumber(50_000L);
        var challenge = Altcha.createChallenge(options);

        var solution = Altcha.solveChallenge(
                challenge.challenge(), challenge.salt(),
                Altcha.Algorithm.fromString(challenge.algorithm()),
                challenge.maxnumber(), 0);

        assertNotNull(solution);
        assertTrue(solution.number() >= 0);

        // Verify the found solution is correct
        var payload = new Altcha.Payload(
                challenge.algorithm(), challenge.challenge(),
                solution.number(), challenge.salt(), challenge.signature());
        assertTrue(Altcha.verifySolution(payload, "secret", false));
    }
}
