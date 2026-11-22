package Lab15_11_2026;

import Lab14_11_2026.TestBitwise;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Encrypt using XOR
 * </p>
 * Message, key the same size, XOR them. If the message is long enough, no one can break it. The problem is that
 * the key becomes itself a message that has to be sent.
 */
public class TestOneTimePath {

    private static final String SEPARATOR = "\\";
    private static final String DEFAULT_PATH = "D:\\ASE\\Master\\Anul_I\\Secure Applictions" +
            "\\java\\laboratory\\15.11.2026";

    private static byte[] encryptDecrypt(byte[] key, byte[] message) {
        if (key.length != message.length) {
            throw new UnsupportedOperationException("Key and Message lengths don't match");
        }

        byte[] cipher = new byte[key.length];

        for (int i = 0; i < key.length; i++) {
            cipher[i] = (byte) (key[i] ^ message[i]);
        }

        return cipher;
    }

    private static void encryptFileOtp(String filePath, byte[] key, String outputFilePath) {
        Path inputFile = Path.of(DEFAULT_PATH + SEPARATOR + filePath);
        if (Files.notExists(inputFile)) {
            throw new RuntimeException(filePath + " does not exist");
        }

        try {
            byte[] fileContent = Files.readAllBytes(inputFile);
            byte[] cypher = encryptDecrypt(key, fileContent);
            Path outputFile = Path.of(DEFAULT_PATH + SEPARATOR + outputFilePath);
            if (!Files.exists(outputFile)) {
                Files.createFile(outputFile);
            }
            try (OutputStream os = Files.newOutputStream(outputFile)) {
                os.write(cypher);
            };
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String key = "abcde";
        String message = "fghji";

        var result = encryptDecrypt(key.getBytes(), message.getBytes());

        System.out.println("Encryption: " + TestBitwise.getHexString(result));
        System.out.println("Decrypt: " + TestBitwise.getHexString(encryptDecrypt(key.getBytes(), result)));

        System.out.println("\n-------------------------------------------------\n");

        File file = new File(DEFAULT_PATH + SEPARATOR + "my_data.bin");
        int fileLength = (int) file.length();
        System.out.println("File length: " + fileLength);

        var randomKey = new byte[fileLength];
        try {
            new SecureRandom().getInstance("SHA1PRNG").nextBytes(randomKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        encryptFileOtp("my_data.bin", randomKey, "my_result_file.bin");
        encryptFileOtp("my_result_file.bin", randomKey, "my_result_file.bin");
    }
}
