package org.altcha.altcha.example;

import org.altcha.altcha.v2.Altcha;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Demonstrates plugging Argon2id into ALTCHA v2 via the {@link Altcha.KeyDerivationFunction}
 * interface, using the Bouncy Castle provider included with {@code spring-security-crypto}.
 *
 * <p>Run with {@code gradle :examples:argon2:run} from the project root.</p>
 */
public class Argon2Example {

    /**
     * Argon2id KDF backed by Bouncy Castle (pulled in transitively by spring-security-crypto).
     *
     * <p>Parameter mapping:</p>
     * <ul>
     *   <li>{@code params.cost()}        → iterations (time cost)</li>
     *   <li>{@code params.memoryCost()}  → memory in KiB (default 65 536 = 64 MB)</li>
     *   <li>{@code params.parallelism()} → lanes / threads (default 1)</li>
     *   <li>{@code params.keyLength()}   → output length in bytes</li>
     * </ul>
     */
    public static final Altcha.KeyDerivationFunction ARGON2_KDF = (params, salt, password) -> {
        var argon2Params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withIterations(params.cost())
                .withMemoryAsKB(params.memoryCost()  != null ? params.memoryCost()  : 65_536)
                .withParallelism(params.parallelism() != null ? params.parallelism() : 1)
                .build();

        var generator = new Argon2BytesGenerator();
        generator.init(argon2Params);

        var derivedKey = new byte[params.keyLength()];
        generator.generateBytes(password, derivedKey);
        return new Altcha.DeriveKeyResult(derivedKey);
    };

    public static void main(String[] args) throws Exception {
        var hmacSecret = "your-secret-key";

        // ----------------------------------------------------------------
        // Server: create a challenge
        // ----------------------------------------------------------------
        var options = new Altcha.CreateChallengeOptions()
                .algorithm("ARGON2ID")   // stored in the challenge; identifies the KDF
                .cost(3)                 // Argon2 time cost (iterations)
                .memoryCost(65_536)      // 64 MB in KiB
                .parallelism(1)
                .hmacSignatureSecret(hmacSecret)
                .deriveKey(ARGON2_KDF);

        var challenge = Altcha.createChallenge(options);
        System.out.println("Challenge JSON:\n" + challenge.toJson());

        // ----------------------------------------------------------------
        // Client: brute-force the counter
        // ----------------------------------------------------------------
        var solution = Altcha.solveChallenge(challenge, ARGON2_KDF);
        System.out.println("\nSolution counter: " + solution.counter());
        System.out.println("Derived key:      " + solution.derivedKey());

        // ----------------------------------------------------------------
        // Server: verify the solution
        // ----------------------------------------------------------------
        var result = Altcha.verifySolution(challenge, solution, hmacSecret, ARGON2_KDF);
        System.out.println("\nVerified: " + result.verified());
    }
}
