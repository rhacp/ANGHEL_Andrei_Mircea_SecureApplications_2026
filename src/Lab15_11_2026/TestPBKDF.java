package Lab15_11_2026;

import Lab14_11_2026.TestBitwise;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class TestPBKDF {

    private static byte[] getPBKDF(String password, byte[] salt, int noIterations, int outputSize) {
        try {
            SecretKeyFactory pbkdfEngine = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec algorithmSpec = new PBEKeySpec(password.toCharArray(), salt, noIterations, outputSize);

            double tStart = System.currentTimeMillis();
            var result = pbkdfEngine.generateSecret(algorithmSpec).getEncoded();
            double tEnd = System.currentTimeMillis();

            System.out.println("Time to generate: " + (tEnd - tStart));
            return result;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        // TO DO: Auto-generated method stub
        String password = "12345678";
        String salt = "salt";
        int noIterations = 100000;
        int outputSize = 80;

        System.out.println("John: " + TestBitwise.getHexString(getPBKDF(password, salt.getBytes(), noIterations, outputSize)));

        System.out.println("\n-------------------------------------------------\n");

        String password1 = "12345678";
        var randomSalt = new byte[5];
        try {
            new SecureRandom().getInstance("SHA1PRNG").nextBytes(randomSalt);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        System.out.println("Bob: " + TestBitwise.getHexString(getPBKDF(password1, randomSalt, noIterations, outputSize)));
    }
}
