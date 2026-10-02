package org.altcha.altcha.internal;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.json.JSONException;
import org.json.JSONTokener;

/**
 * JSON parsing for untrusted client payloads, shared by the v1 and v2 APIs. Not exported by the
 * module; not part of the public API.
 *
 * <p>Parses like JS {@code JSON.parse} in linear time. org.json's own number parsing goes through
 * BigInteger/BigDecimal, which is quadratic in the digit count: a single unauthenticated payload
 * with a 1M-digit number cost ~10 s of CPU.
 */
public final class Json {
    private Json() {}

    /** Decodes base64 and parses the JSON document with {@link #parse}; trailing content is an error. */
    public static Object parseBase64(String base64Payload) {
        var x = new JSONTokener(new String(Base64.getDecoder().decode(base64Payload), StandardCharsets.UTF_8));
        var value = parse(x);
        if (x.nextClean() != 0) throw x.syntaxError("Unexpected trailing content");
        return value;
    }

    /**
     * Parses a JSON value like JS {@code JSON.parse}: objects become insertion-ordered maps
     * (a duplicate key keeps its first position and its last value), arrays become lists,
     * {@code null} becomes Java {@code null}.
     */
    private static Object parse(JSONTokener x) {
        var c = x.nextClean();
        if (c == '{') {
            var map = new LinkedHashMap<String, Object>();
            if (x.nextClean() == '}') return map;
            x.back();
            while (true) {
                if (x.nextClean() != '"') throw x.syntaxError("Expected a string key");
                var key = x.nextString('"');
                if (x.nextClean() != ':') throw x.syntaxError("Expected ':' after key");
                map.put(key, parse(x));
                c = x.nextClean();
                if (c == '}') return map;
                if (c != ',') throw x.syntaxError("Expected ',' or '}'");
            }
        }
        if (c == '[') {
            var list = new ArrayList<Object>();
            if (x.nextClean() == ']') return list;
            x.back();
            while (true) {
                list.add(parse(x));
                c = x.nextClean();
                if (c == ']') return list;
                if (c != ',') throw x.syntaxError("Expected ',' or ']'");
            }
        }
        if (c == '"') return x.nextString('"');
        var token = new StringBuilder();
        for (; c != 0 && ",:]} \t\n\r".indexOf(c) < 0; c = x.next()) token.append(c);
        if (c != 0) x.back();
        return scalar(token.toString(), x);
    }

    private static final Pattern NUMBER =
            Pattern.compile("-?+(?:0|[1-9]\\d*+)(\\.\\d++)?+([eE][+-]?+\\d++)?+");

    /**
     * A JSON literal or number. Integer literals keep org.json's types ({@code Integer}, else
     * {@code Long}); anything else becomes the nearest {@code Double}, as in JS.
     */
    private static Object scalar(String token, JSONTokener x) {
        switch (token) {
            case "true":  return Boolean.TRUE;
            case "false": return Boolean.FALSE;
            case "null":  return null;
            default:      break;
        }
        var m = NUMBER.matcher(token);
        if (!m.matches()) {
            throw x.syntaxError("Unexpected token '" + token.substring(0, Math.min(token.length(), 32)) + "'");
        }
        if (m.group(1) == null && m.group(2) == null && token.length() <= 20) {
            try {
                var l = Long.parseLong(token);
                if (l == (int) l) return (int) l;
                return l;
            } catch (NumberFormatException beyondLong) {
                // falls through to the nearest double
            }
        }
        return Double.parseDouble(token);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object value, String name) {
        if (!(value instanceof Map<?, ?>)) throw new JSONException("\"" + name + "\" is not a JSON object");
        return (Map<String, Object>) value;
    }

    /** A required string field, like org.json {@code getString}. */
    public static String requiredString(Map<String, Object> map, String key) {
        if (map.get(key) instanceof String s) return s;
        throw new JSONException("\"" + key + "\" is not a string");
    }

    /** An optional field as a string, like org.json {@code optString(key, null)}. */
    public static String optionalString(Map<String, Object> map, String key) {
        var value = map.get(key);
        return value == null ? null : value.toString();
    }

    /** A required numeric field, like org.json {@code getInt}/{@code getLong}/{@code getDouble}: a number or a numeric string. */
    public static <T> T requiredNumber(Map<String, Object> map, String key,
            Function<String, T> parse, Function<Number, T> convert) {
        var value = map.get(key);
        if (value instanceof Number n) return convert.apply(n);
        if (value == null) throw new JSONException("\"" + key + "\" not found");
        try {
            return parse.apply(value.toString());
        } catch (NumberFormatException e) {
            throw new JSONException("\"" + key + "\" is not a number", e);
        }
    }

    /** A required boolean field, like org.json {@code getBoolean}: a boolean or "true"/"false" (any case). */
    public static boolean requiredBoolean(Map<String, Object> map, String key) {
        var value = map.get(key);
        if (value instanceof Boolean b) return b;
        if (value instanceof String s) {
            if (s.equalsIgnoreCase("true")) return true;
            if (s.equalsIgnoreCase("false")) return false;
        }
        throw new JSONException("\"" + key + "\" is not a boolean");
    }
}
