package Lab15_11_2026;

import Lab14_11_2026.TestBitwise;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class TestMAC {

    private static final String SEPARATOR = "\\";
    private static final String DEFAULT_PATH = "D:\\ASE\\Master\\Anul_I\\Secure Applictions" +
            "\\java\\laboratory\\15.11.2026";

    public static byte[] getHashMAC(String message, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec secret = new SecretKeySpec(key.getBytes(), "HmacSHA1");
            mac.init(secret);
            return mac.doFinal(message.getBytes());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getFileHashMAC(String filePath, String key) {
        Path path =  Paths.get(DEFAULT_PATH + SEPARATOR + filePath);
        if (!path.toFile().exists()) {
            throw new RuntimeException(path + " does not exist");
        }

        try (InputStream is = Files.newInputStream(path)) {
            Mac mac = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret = new SecretKeySpec(key.getBytes(), "HmacSHA512");
            mac.init(secret);
            byte[] buffer = new byte[5];
            int noOfBytesWeGot = 0;
            while((noOfBytesWeGot = is.read(buffer)) != -1) {
                mac.update(buffer, 0, noOfBytesWeGot);
            }
            mac.init(secret);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String message = "Hello World!!";
        String key = "12345678";

        System.out.println("HMAC: " + TestBitwise.getHexString(getHashMAC(message, key)));

        System.out.println("\n-------------------------------------------------\n");

        System.out.println("File HMAC: " + TestBitwise.getHexString(getFileHashMAC("my_data.bin", key)));
    }
}
