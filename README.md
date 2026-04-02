# ALTCHA Java Library

The ALTCHA Java Library is a lightweight library designed for creating and verifying [ALTCHA](https://altcha.org) challenges.

## Compatibility

- Java 17+

## Examples

- [`examples/server/`](/examples/server/)  
        Minimal ALTCHA v2 example server. Run: `gradle :examples:server:run`
- [`examples/argon2/`](/examples/argon2/)  
        Example using Argon2id algorithm. Run: `gradle :examples:argon2:run`

## Installation

Maven Central: [org.altcha/altcha](https://central.sonatype.com/artifact/org.altcha/altcha)

Maven:

```xml
<dependency>
    <groupId>org.altcha</groupId>
    <artifactId>altcha</artifactId>
    <version>2.0.0</version>
</dependency>
```

Gradle:

```
implementation 'org.altcha:altcha:2.0.0'
```

`org.json` must be present at runtime (it is a `provided` dependency):

```xml
<dependency>
    <groupId>org.json</groupId>
    <artifactId>json</artifactId>
    <version>20240303</version>
</dependency>
```

## Protocol versions

| Version | Package | Algorithm |
|---------|---------|-----------|
| **v1** (legacy) | `org.altcha.altcha.v1` | SHA-1 / SHA-256 / SHA-512 |
| **v2** | `org.altcha.altcha.v2` | PBKDF2 / SHA-iterative (pluggable KDF) |

Both versions live side-by-side. Use `org.altcha.altcha.v2` for new integrations.

---

## v2 Usage

v2 uses a configurable key-derivation function (KDF). The server creates a signed challenge; the client brute-forces a counter until the derived key starts with the required prefix.

### Create a challenge (server)

```java
import org.altcha.altcha.v2.Altcha;

var options = new Altcha.CreateChallengeOptions()
        .algorithm("PBKDF2/SHA-256")
        .cost(5_000)          // PBKDF2 iterations
        .hmacSignatureSecret("your-secret-key")
        .expiresInSeconds(600); // 10 minutes

Altcha.Challenge challenge = Altcha.createChallenge(options);
// Serialize challenge to JSON and send to client
```

**Supported algorithms (built-in):**

| String | KDF |
|--------|-----|
| `"PBKDF2/SHA-256"` | PBKDF2-HMAC-SHA-256 |
| `"PBKDF2/SHA-384"` | PBKDF2-HMAC-SHA-384 |
| `"PBKDF2/SHA-512"` | PBKDF2-HMAC-SHA-512 |
| `"SHA-256"` | Iterative SHA-256 |
| `"SHA-384"` | Iterative SHA-384 |
| `"SHA-512"` | Iterative SHA-512 |

External KDFs (Argon2id, Scrypt) can be plugged in via the `KeyDerivationFunction` interface.

### Solve a challenge (client-side utility)

```java
var kdf      = Altcha.kdf(challenge.parameters().algorithm());
var solution = Altcha.solveChallenge(challenge, kdf);
// Encode {challenge, solution} as JSON, base64 it, and submit
```

### Verify a solution (server)

```java
// From a base64-encoded payload submitted by the client:
Altcha.VerifySolutionResult result = Altcha.verifySolution(
        base64Payload,
        "your-secret-key",
        Altcha.kdf("PBKDF2/SHA-256"));

if (result.verified()) {
    // accept
} else if (result.expired()) {
    // challenge expired
} else if (Boolean.TRUE.equals(result.invalidSignature())) {
    // challenge was tampered with
}
```

Or from already-parsed objects:

```java
Altcha.VerifySolutionResult result = Altcha.verifySolution(
        challenge, solution, "your-secret-key", kdf);
```

### Custom metadata / expiry

```java
var options = new Altcha.CreateChallengeOptions()
        .algorithm("PBKDF2/SHA-256")
        .cost(5_000)
        .hmacSignatureSecret("secret")
        .expiresInSeconds(300)
        .data(Map.of("userId", "42", "action", "login"));
```

### Deterministic mode (key signature)

In deterministic mode the server pre-computes the expected key prefix from a known counter. This allows fast verification without re-running the KDF.

```java
var options = new Altcha.CreateChallengeOptions()
        .algorithm("SHA-256")
        .cost(5_000)
        .counter(123)                              // random counter
        .hmacSignatureSecret("secret")
        .hmacKeySignatureSecret("key-secret");     // signs the derived key

Altcha.Challenge challenge = Altcha.createChallenge(options);

// Verify using key signature (fast — no KDF re-invocation)
Altcha.VerifySolutionResult result = Altcha.verifySolution(
        challenge, solution, "secret", "key-secret", null, null);
```

### Pluggable KDF (e.g. Argon2id)

```java
Altcha.KeyDerivationFunction argon2id = (params, salt, password) -> {
    byte[] dk = /* your Argon2id library */ computeArgon2id(
            password, salt,
            params.cost(),          // time cost
            params.memoryCost(),    // memory in KiB
            params.parallelism(),
            params.keyLength());
    return new Altcha.DeriveKeyResult(dk);
};

var options = new Altcha.CreateChallengeOptions()
        .algorithm("ARGON2ID")
        .cost(3)
        .memoryCost(65536)
        .parallelism(1)
        .deriveKey(argon2id)
        .hmacSignatureSecret("secret");
```

### Fields hash (ALTCHA Sentinel)

```java
boolean ok = Altcha.verifyFieldsHash(formData, fields, fieldsHash, "SHA-256");
```

### Server signature (ALTCHA Sentinel)

```java
Altcha.ServerSignatureVerification result =
        Altcha.verifyServerSignature(base64Payload, "secret");

if (result.verified()) {
    double score = result.verificationData().score();
}
```

---

## v1 Usage (legacy)

v1 uses simple hashcash-style proof-of-work. It is preserved for backward compatibility.

```java
import org.altcha.altcha.v1.Altcha;

// Create challenge
var options = new Altcha.ChallengeOptions()
        .hmacKey("secret")
        .maxNumber(1_000_000L)
        .expiresInSeconds(600);

Altcha.Challenge challenge = Altcha.createChallenge(options);

// Verify solution (base64 payload from client)
boolean valid = Altcha.verifySolution(base64Payload, "secret", true);
```

### v1 API reference

| Method | Description |
|--------|-------------|
| `createChallenge(ChallengeOptions)` | Creates a new challenge |
| `verifySolution(Payload, String, boolean)` | Verifies a typed payload |
| `verifySolution(String, String, boolean)` | Verifies a base64 JSON payload |
| `solveChallenge(String, String, Algorithm, long, long)` | Brute-forces a solution (client utility) |
| `extractParams(String)` | Parses params embedded in a salt |
| `verifyFieldsHash(Map, String[], String, Algorithm)` | Verifies a Sentinel fields hash |
| `verifyServerSignature(ServerSignaturePayload, String)` | Verifies a Sentinel server signature |
| `verifyServerSignature(String, String)` | Verifies from a base64 payload |

---

## Random Number Generator

**v2** always uses `SecureRandom` for the nonce and salt, as these values must be unpredictable.

**v1** uses a non-secure random number generator by default to avoid blocking on low-entropy systems. To opt in to a cryptographically secure RNG:

```java
new Altcha.ChallengeOptions().secureRandomNumber(true)
```

On low-entropy systems (e.g. containers at startup), `SecureRandom` may block. If that happens, add this JVM option:

```
-Djava.security.egd=file:/dev/./urandom
```

This applies to both v1 (when `secureRandomNumber` is enabled) and v2.

## License

MIT
