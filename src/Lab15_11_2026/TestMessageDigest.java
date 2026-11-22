package Lab15_11_2026;

import Lab14_11_2026.TestBitwise;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Class to play with MD5(128bits), SHA1(128bits), SHA2(256bits)
 */
public class TestMessageDigest {

    private static final String SEPARATOR = "\\";
    private static final String DEFAULT_PATH = "D:\\ASE\\Master\\Anul_I\\Secure Applictions" +
            "\\java\\laboratory\\15.11.2026";

    private static byte[] getHash(String password) {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-1");
            return hash.digest(password.getBytes());

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] getFileHash(String filePath) {
        File file = new File(DEFAULT_PATH + SEPARATOR + filePath);


        if (!file.exists()) {
            throw new RuntimeException(String.format("File does not exist: %s", filePath));
        }

        try (var fis = new FileInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] buffer = new byte[8];
            int noOfBytesWeGot = 0;
            while((noOfBytesWeGot = fis.read(buffer)) != -1) {
                md.update(buffer, 0, noOfBytesWeGot);
            }
            return md.digest();
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String password = "12345678";
        System.out.println("SHA-1 Hash: " + TestBitwise.getHexString(getHash(password)));

        System.out.println("\n----------------------------------------------------" +
                "----------------------------------------------\n");

        System.out.println("MD5 Hash of File: " + TestBitwise.getHexString(getFileHash("my_data.bin")));
    }
}