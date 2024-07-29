# ALTCHA Java Library

The ALTCHA Java Library is a lightweight library designed for creating and verifying [ALTCHA](https://altcha.org) challenges.

## Compatibility

This library is compatible with:

- Java 8+

## Example

- [Demo server](https://github.com/altcha-org/altcha-starter-java)

## Installation

To install the ALTCHA Java Library, add [JitPack](https://jitpack.io) repository to your `pom.xml` if you use Maven:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

and add the following dependency:

```xml
<dependency>
    <groupId>com.github.altcha-org</groupId>
    <artifactId>altcha-lib-java</artifactId>
    <version>v1.0.0</version>
</dependency>
```

For Gradle, follow the guide in the [JitPack's documentation](https://jitpack.io).

<!--
To install the ALTCHA Java Library, add the following dependency to your `pom.xml` if you use Maven:

```xml
<dependency>
    <groupId>org.altcha</groupId>
    <artifactId>altcha</artifactId>
    <version>1.0.0</version>
</dependency>
```

Or, if you use Gradle, add the following to your `build.gradle`:

```groovy
implementation 'org.altcha:altcha:1.0.0'
```
-->
## Warning
This library relies on SecureRandom which may hang if there is not sufficient 'noise' on your Linux server.
One fix is to add this to your JVM invocation:
```
-Djava.security.egd=file:/dev/./urandom
```


## Usage

Here’s a basic example of how to use the ALTCHA Java Library:

```java
import java.util.HashMap;
import java.util.Map;

import org.altcha.altcha.Altcha;
import org.altcha.altcha.Altcha.ChallengeOptions;

public class Example {
    public static void main(String[] args) {
        String hmacKey = "secret hmac key";

        try {
            // Create a new challenge
            ChallengeOptions options = new ChallengeOptions()
                .setMaxNumber(100000L) // the maximum random number
                .setHmacKey(hmacKey)
                .setExpiresInSeconds(3600) // 1 hour expiration

            System.out.println("Challenge created: " + challenge);

            // Example payload to verify
            Map<String, Object> payload = new HashMap<>();
            payload.put("algorithm", challenge.algorithm);
            payload.put("challenge", challenge.challenge);
            payload.put("number", 12345); // Example number
            payload.put("salt", challenge.salt);
            payload.put("signature", challenge.signature);

            // Verify the solution
            boolean isValid = Altcha.verifySolution(payload, hmacKey, true);

            if (isValid) {
                System.out.println("Solution verified!");
            } else {
                System.out.println("Invalid solution.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## API

### `createChallenge(ChallengeOptions options)`

Creates a new challenge for ALTCHA.

**Parameters:**

- `ChallengeOptions options`: Options for creating the challenge.

**Returns:** `Challenge`

### `verifySolution(Payload payload, String hmacKey, boolean checkExpires)`

Verifies an ALTCHA solution using a `Payload` object.

**Parameters:**

- `Payload payload`: The solution payload to verify.
- `String hmacKey`: The HMAC key used for verification.
- `boolean checkExpires`: Whether to check if the challenge has expired.

**Returns:** `boolean`

### `verifySolution(String base64Payload, String hmacKey, boolean checkExpires)`

Verifies an ALTCHA solution using a base64-encoded JSON string.

**Parameters:**

- `String base64Payload`: Base64-encoded JSON payload to verify.
- `String hmacKey`: The HMAC key used for verification.
- `boolean checkExpires`: Whether to check if the challenge has expired.

**Returns:** `boolean`

### `extractParams(String salt)`

Extracts URL parameters from the salt.

**Parameters:**

- `String salt`: The salt string containing URL parameters.

**Returns:** `Map<String, String>`

### `verifyFieldsHash(Map<String, String> formData, List<String> fields, String fieldsHash, Algorithm algorithm)`

Verifies the hash of form fields.

**Parameters:**

- `Map<String, String> formData`: The form data to hash.
- `List<String> fields`: The fields to include in the hash.
- `String fieldsHash`: The expected hash value.
- `Algorithm algorithm`: Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).

**Returns:** `boolean`

### `verifyServerSignature(ServerSignaturePayload payload, String hmacKey)`

Verifies the server signature using a `ServerSignaturePayload` object.

**Parameters:**

- `ServerSignaturePayload payload`: The payload to verify.
- `String hmacKey`: The HMAC key used for verification.

**Returns:** `boolean, ServerSignatureVerificationData`

### `verifyServerSignature(String base64Payload, String hmacKey)`

Verifies the server signature using a base64-encoded JSON string.

**Parameters:**

- `String base64Payload`: Base64-encoded JSON payload to verify.
- `String hmacKey`: The HMAC key used for verification.

**Returns:** `boolean, ServerSignatureVerificationData`

### `solveChallenge(String challenge, String salt, Algorithm algorithm, int max, int start)`

Finds a solution to the given challenge.

**Parameters:**

- `String challenge`: The challenge hash.
- `String salt`: The challenge salt.
- `Algorithm algorithm`: Hashing algorithm (`SHA-1`, `SHA-256`, `SHA-512`).
- `int max`: Maximum number to iterate to.
- `int start`: Starting number.

**Returns:** `Solution`

## License

MIT