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
    <version>2.1.0</version>
</dependency>
```

Gradle:

```
implementation 'org.altcha:altcha:2.1.0'
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
var solution = Altcha.solveChallenge(challenge, kdf);  // null if not solved within 90 s
// Encode {challenge, solution} as JSON, base64 it, and submit
```

Like the JavaScript library, `solveChallenge` gives up after `Altcha.DEFAULT_SOLVE_TIMEOUT` (90 s) and returns `null`; pass a `Duration` to change it (`null` or zero disables it). To abort a running solve, interrupt its thread (e.g. `Future.cancel(true)`); it then throws `InterruptedException`.

```java
var solution = Altcha.solveChallenge(challenge, kdf, 0, 1, Duration.ofSeconds(10));
```

### Verify a solution (server)

```java
// From a base64-encoded payload submitted by the client:
Altcha.VerifySolutionResult result = Altcha.verifySolution(
        base64Payload,
        "your-secret-key",
        Altcha.kdf("PBKDF2/SHA-256"));

// Challenges created with hmacAlgorithm / counterMode must be verified with the same values:
Altcha.VerifySolutionResult result384 = Altcha.verifySolution(
        base64Payload, "your-secret-key", null, "SHA-384", null, Altcha.kdf("PBKDF2/SHA-256"));

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

`data` values must be JSON types: `String`, `Number`, `Boolean`, `null`, `Map` or `List`. Signing uses the same canonical JSON as the JavaScript library (`JSON.stringify` with recursively sorted keys), so signatures interoperate with it and survive the widget's JSON round trip: numbers are formatted like JavaScript (`1.0` → `1`, `1e21` → `1e+21`), and objects inside a `List` are not sorted but keep their iteration order — use a `LinkedHashMap` for those.

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

// Verify using key signature (fast — no KDF re-invocation).
// The 5th argument is the HMAC algorithm (null = "SHA-256"); it must match CreateChallengeOptions.hmacAlgorithm.
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

A KDF can also return updated parameters, e.g. defaults it picked:
`new Altcha.DeriveKeyResult(dk, updatedParams)`. In deterministic mode (`counter` set) `createChallenge` uses them in place of the challenge parameters before computing `keyPrefix` and signing, like the JavaScript library. Solve and verify ignore them.

### Counter mode

By default the counter is appended to the nonce as a big-endian 32-bit integer (`CounterMode.UINT32`). `CounterMode.STRING` appends its decimal digits instead, for compatibility with the JavaScript library's `counterMode: 'string'`. The mode is not part of the signed challenge, so creator, solver and verifier must use the same one:

```java
options.counterMode(Altcha.CounterMode.STRING);
var solution = Altcha.solveChallenge(challenge, kdf, 0, 1, Altcha.DEFAULT_SOLVE_TIMEOUT, Altcha.CounterMode.STRING);
var result   = Altcha.verifySolution(challenge, solution, "secret", null, null, Altcha.CounterMode.STRING, kdf);
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
    var data     = result.verificationData();
    Number score = data.score();                        // null if absent
    var reasons  = data.reasons();                      // empty list if none
    var country  = data.get("location.countryCode");    // any field, typed like JS
}
```

Verification data is parsed like the JavaScript library's `parseVerificationData`: `true`/`false` become `Boolean`, integers `Long`, decimals `Double`, everything else a trimmed `String`; non-empty `fields`/`reasons` become a `List<String>`. `result.toJson()` has the same fields as the JavaScript result (`expired`, `invalidSignature`, `invalidSolution`, `time`, `verificationData`, `verified`).

### v2 API reference

#### Static methods

| Method | Returns | Description |
|--------|---------|-------------|
| `createChallenge(CreateChallengeOptions)` | `Challenge` | Creates a new signed v2 challenge |
| `signChallenge(String, ChallengeParameters, byte[], String, String)` | `Challenge` | Signs challenge parameters with HMAC |
| `solveChallenge(Challenge, KeyDerivationFunction)` | `Solution` | Brute-forces a solution (counter start=0, step=1, 90 s timeout; `null` on timeout) |
| `solveChallenge(Challenge, KeyDerivationFunction, long, long)` | `Solution` | Brute-forces a solution with custom start/step (90 s timeout) |
| `solveChallenge(Challenge, KeyDerivationFunction, long, long, Duration)` | `Solution` | Same, with a custom timeout (`null`/zero = none) |
| `solveChallenge(Challenge, KeyDerivationFunction, long, long, Duration, CounterMode)` | `Solution` | Same, with a counter mode (`null` = `UINT32`) |
| `verifySolution(String, String, KeyDerivationFunction)` | `VerifySolutionResult` | Verifies a base64 JSON payload from the client |
| `verifySolution(String, String, String, KeyDerivationFunction)` | `VerifySolutionResult` | Same, with optional key-signature secret (fast path; KDF may be `null`) |
| `verifySolution(String, String, String, String, CounterMode, KeyDerivationFunction)` | `VerifySolutionResult` | Same, with HMAC algorithm and counter mode (`null` = `SHA-256` / `UINT32`) |
| `verifySolution(Challenge, Solution, String, KeyDerivationFunction)` | `VerifySolutionResult` | Verifies typed challenge + solution objects |
| `verifySolution(Challenge, Solution, String, String, KeyDerivationFunction)` | `VerifySolutionResult` | Verifies with optional key-signature secret (fast path) |
| `verifySolution(Challenge, Solution, String, String, String, KeyDerivationFunction)` | `VerifySolutionResult` | Same, with explicit HMAC algorithm (WebCrypto names `SHA-256`/`SHA-384`/`SHA-512`/`SHA-1`, case-insensitive; `null` = `SHA-256`; other names throw) for challenges created with `hmacAlgorithm` |
| `verifySolution(Challenge, Solution, String, String, String, CounterMode, KeyDerivationFunction)` | `VerifySolutionResult` | Same, with a counter mode (`null` = `UINT32`) |
| `parsePayload(String)` | `Payload` | Decodes a base64 JSON payload into typed objects (parsed like JS `JSON.parse`: non-standard JSON such as `01`, `'a'` or unquoted strings is rejected) |
| `isServerSignaturePayload(String)` | `boolean` | Returns `true` if the payload is from the Sentinel service |
| `verifyFieldsHash(Map<String,String>, String[], String, String)` | `boolean` | Verifies a Sentinel fields hash |
| `verifyServerSignature(ServerSignaturePayload, String)` | `ServerSignatureVerification` | Verifies a typed Sentinel server-signature payload |
| `verifyServerSignature(String, String)` | `ServerSignatureVerification` | Verifies a base64-encoded Sentinel payload |
| `kdf(String)` | `KeyDerivationFunction` | Returns the built-in KDF for the given algorithm string |
| `pbkdf2()` | `KeyDerivationFunction` | PBKDF2-based KDF factory |
| `sha()` | `KeyDerivationFunction` | SHA-iterative KDF factory |
| `randomBytes(int)` | `byte[]` | Generates cryptographically random bytes |
| `bytesToHex(byte[])` | `String` | Encodes a byte array as a lowercase hex string |

#### Data types

| Type | Kind | Description |
|------|------|-------------|
| `CreateChallengeOptions` | mutable builder | Options for `createChallenge` — algorithm, cost, secrets, expiry, data, KDF override |
| `ChallengeParameters` | record | Parameters embedded in a challenge (algorithm, nonce, salt, cost, keyPrefix, …) |
| `Challenge` | record | Challenge object sent to the client: `parameters` + HMAC `signature` |
| `Solution` | record | Solution found by the client: `counter`, `derivedKey`, `time` (ms, 1 decimal) |
| `Payload` | record | Full client submission: `challenge` + `solution` |
| `VerifySolutionResult` | record | Verification outcome: `verified`, `expired`, `invalidSignature`, `invalidSolution` (`null` when not checked), `time` (ms, 1 decimal); `toJson()` matches the JS result |
| `ServerSignaturePayload` | record | Raw Sentinel attestation payload |
| `ServerSignatureVerification` | record | Sentinel verification result: `verified`, `expired`, `invalidSignature`, `invalidSolution`, `time`, `verificationData`; `toJson()` matches the JS result |
| `ServerSignatureVerificationData` | record | Parsed Sentinel data: `values()` (all fields, JS-typed), `get(name)`, and typed accessors `score`, `classification`, `email`, `expire`, `fields`, `reasons`, … |
| `KeyDerivationFunction` | functional interface | Pluggable KDF: `deriveKey(ChallengeParameters, byte[] salt, byte[] password)` |
| `DeriveKeyResult` | record | `derivedKey` returned by a KDF, plus optional `parameters` merged into the challenge by `createChallenge` |
| `CounterMode` | enum | Counter encoding in the KDF password: `UINT32` (default) or `STRING` |
| `PasswordBuffer` | class | Combines nonce + counter into the KDF password for each iteration |

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
