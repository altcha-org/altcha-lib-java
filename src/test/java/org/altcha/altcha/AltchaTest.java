package org.altcha.altcha;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AltchaTest {

    @Test
    public void testRandomBytes() {
        byte[] bytes = Altcha.randomBytes(16);
        assertNotNull(bytes);
        assertEquals(16, bytes.length);
    }

    @Test
    public void testRandomInt() {
        int max = 100;
        int random = Altcha.randomInt(max);
        assertTrue(random >= 0 && random <= max);
    }

    @Test
    public void testHashHex() throws Exception {
        String data = "hello";
        String hash = Altcha.hashHex(Altcha.Algorithm.SHA256, data);
        assertNotNull(hash);
        assertEquals(64, hash.length()); // SHA-256 produces a 64-character hex string
    }

    @Test
    public void testHmacHex() throws Exception {
        String data = "hello";
        String key = "secret";
        String hmac = Altcha.hmacHex(Altcha.Algorithm.SHA256, data.getBytes(StandardCharsets.UTF_8), key);
        assertNotNull(hmac);
        assertEquals(64, hmac.length()); // HMAC-SHA256 produces a 64-character hex string
    }

    @Test
    public void testCreateChallenge() throws Exception {
        Altcha.ChallengeOptions options = new Altcha.ChallengeOptions();
        options.hmacKey = "secret";

        Altcha.Challenge challenge = Altcha.createChallenge(options);
        assertNotNull(challenge);
        assertEquals(Altcha.DEFAULT_ALGORITHM.getName(), challenge.algorithm);
        assertTrue(challenge.maxnumber > 0);
        assertNotNull(challenge.salt);
        assertNotNull(challenge.signature);
        assertNotNull(challenge.challenge);
    }

    @Test
    public void testVerifySolution() throws Exception {
        Altcha.ChallengeOptions options = new Altcha.ChallengeOptions();
        options.number = 100L;
        options.hmacKey = "secret";

        Altcha.Challenge challenge = Altcha.createChallenge(options);

        Altcha.Payload payload = new Altcha.Payload();
        payload.algorithm = challenge.algorithm;
        payload.challenge = challenge.challenge;
        payload.number = options.number;
        payload.salt = challenge.salt;
        payload.signature = challenge.signature;

        boolean isValid = Altcha.verifySolution(payload, options.hmacKey, false);
        assertTrue(isValid);
    }

    @Test
    public void testExtractParams() throws Exception {
        Map<String, String> params = Altcha.extractParams("testSalt?param1=value1&param2=value2");
        assertEquals(2, params.size());
        assertEquals("value1", params.get("param1"));
        assertEquals("value2", params.get("param2"));
    }

    @Test
    public void testVerifyFieldsHash() throws Exception {
        Map<String, String> formData = new HashMap<>();
        formData.put("field1", "value1");
        formData.put("field2", "value2");

        String[] fields = {"field1", "field2"};
        String joinedData = "value1\nvalue2";
        String computedHash = Altcha.hashHex(Altcha.Algorithm.SHA256, joinedData);

        boolean isValid = Altcha.verifyFieldsHash(formData, fields, computedHash, Altcha.Algorithm.SHA256);
        assertTrue(isValid);
    }

    @Test
    public void testVerifyServerSignature() throws Exception {
        Altcha.ServerSignaturePayload payload = new Altcha.ServerSignaturePayload();
        payload.algorithm = Altcha.Algorithm.SHA256;
        payload.verificationData = "score=3&verified=true";
        byte[] hash = Altcha.hash(payload.algorithm, payload.verificationData.getBytes(StandardCharsets.UTF_8));
        payload.signature = Altcha.hmacHex(Altcha.Algorithm.SHA256, hash, "secret");
        payload.verified = true;

        boolean isValid = Altcha.verifyServerSignature(payload, "secret");
        assertTrue(isValid);
    }

    @Test
    public void testSolveChallenge() throws Exception {
        Altcha.ChallengeOptions options = new Altcha.ChallengeOptions();
        options.hmacKey = "secret";

        Altcha.Challenge challenge = Altcha.createChallenge(options);

        Altcha.Solution solution = Altcha.solveChallenge(challenge.challenge, challenge.salt, Altcha.Algorithm.fromString(challenge.algorithm), challenge.maxnumber, 0);
        assertNotNull(solution);
        assertTrue(solution.number >= 0);
        assertTrue(solution.took > 0);
    }
}

