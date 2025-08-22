package org.kaiden.jwtauthentication.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class PasswordHasher {
    private static final int ITERATIONS = 120_000;
    private static final int KEY_LENGTH = 256;
    private static final SecureRandom RAND = new SecureRandom();

    private static byte[] pbkdf2(char[] pwd, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(pwd, salt, ITERATIONS, KEY_LENGTH);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String hash(String password) {
        byte[] salt = new byte[16];
        RAND.nextBytes(salt);
        byte[] hash = pbkdf2(password.toCharArray(), salt);
        return Base64.getEncoder().encodeToString(salt) + ":" +
                Base64.getEncoder().encodeToString(hash);
    }

    public static boolean verify(String password, String stored) {
        if (stored == null) return false;
        int sep = stored.indexOf(':');
        if (sep <= 0 || sep == stored.length() - 1) return false;

        try {
            byte[] salt = Base64.getDecoder().decode(stored.substring(0, sep));
            byte[] expected = Base64.getDecoder().decode(stored.substring(sep + 1));
            char[] pwd = password != null ? password.toCharArray() : new char[0];

            byte[] actual = pbkdf2(pwd, salt);
            if (actual.length != expected.length) return false;

            int diff = 0;
            for (int i = 0; i < actual.length; i++) diff |= (actual[i] ^ expected[i]);
            return diff == 0;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
