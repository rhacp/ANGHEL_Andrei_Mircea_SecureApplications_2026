package Lab21_11_20267;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class TestECB {

    private static final String SEPARATOR = "\\";
    private static final String PKCS5_PADDING = "/ECB/PKCS5Padding";
    private static final String DEFAULT_PATH = "D:\\ASE\\Master\\Anul_I\\Secure Applictions" +
            "\\java\\laboratory\\15.11.2026";

    public static void main(String[] args) {
        // 16 bytes
        String key = "passwordism12345";

        System.out.println("ENCRYPT");
        encrypt(key.getBytes(), "AES", DEFAULT_PATH + SEPARATOR + "message.txt",
                DEFAULT_PATH + SEPARATOR + "message.enc");

        // AES
        // Important: Usually, the enc file will have 32 bytes (but for a longer input, like 16 bytes message.txt)
        // If you make the message 32 bytes (multiple of 16 apparently), the end will be 48 bytes
        // If you make the message small (< 16 bytes), you will get 16

        // The safest way to check is to decrypt

        System.out.println("\n----------------------------------------------\n");

        System.out.println("DECRYPT");
        decrypt(key.getBytes(), "AES", DEFAULT_PATH + SEPARATOR + "message.enc",
                DEFAULT_PATH + SEPARATOR + "result.txt");

        System.out.println("\n----------------------------------------------\n");

        System.out.println("PROCESS");
        process(key.getBytes(), "AES", DEFAULT_PATH + SEPARATOR + "message.txt",
                DEFAULT_PATH + SEPARATOR + "message.enc", Mode.ENC);
        process(key.getBytes(), "AES", DEFAULT_PATH + SEPARATOR + "message.enc",
                DEFAULT_PATH + SEPARATOR + "result.txt", Mode.DEC);
    }

    private static void process(byte[] key, String algorithm, String inputFile, String outputFile, Mode mode) {
        File input = new File(inputFile);
        File output = new File(outputFile);

        if (!input.exists()) {
            throw new IllegalArgumentException(String.format("File %s does not exist", inputFile));
        } else if (!output.exists()) {
            throw new IllegalArgumentException(String.format("File %s does not exist", outputFile));
        }

        try (var fis = new FileInputStream(input); var fos = new FileOutputStream(output)) {
            // Create cipher text
            Cipher cipher = Cipher.getInstance(algorithm + PKCS5_PADDING);

            // Invalid key exception means that they key has a different size than the algorithm result
            initCipher(mode, cipher, key, algorithm);

            byte[] block = new byte[cipher.getBlockSize()];
            int noBytesWeGot = 0;

            // 0 - eof; -1 after end of file
            while ((noBytesWeGot = fis.read(block)) > 0) {
                // Encrypt current block
                byte[] cipherBlock = cipher.update(block, 0, noBytesWeGot);
                fos.write(cipherBlock);
            }

            // Don't forget the last one
            fos.write(cipher.doFinal());

        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private static void encrypt(byte[] key, String algorithm, String inputFile, String outputFile) {
        File input = new File(inputFile);
        File output = new File(outputFile);

        if (!input.exists()) {
            throw new IllegalArgumentException(String.format("File %s does not exist", inputFile));
        } else if (!output.exists()) {
            throw new IllegalArgumentException(String.format("File %s does not exist", outputFile));
        }

        try (var fis = new FileInputStream(input); var fos = new FileOutputStream(output)) {
            // Create cipher text
            Cipher cipher = Cipher.getInstance(algorithm + PKCS5_PADDING);

            // Invalid key exception means that they key has a different size than the algorithm result
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm));

            byte[] block = new byte[cipher.getBlockSize()];
            int noBytesWeGot = 0;

            // 0 - eof; -1 after end of file
            while ((noBytesWeGot = fis.read(block)) > 0) {
                // Encrypt current block
                byte[] cipherBlock = cipher.update(block, 0, noBytesWeGot);
                fos.write(cipherBlock);
            }

            // Don't forget the last one
            fos.write(cipher.doFinal());

        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private static void decrypt(byte[] key, String algorithm, String inputFile, String outputFile) {
        File input = new File(inputFile);
        File output = new File(outputFile);

        if (!input.exists()) {
            throw new IllegalArgumentException(String.format("File %s does not exist", inputFile));
        } else if (!output.exists()) {
            throw new IllegalArgumentException(String.format("File %s does not exist", outputFile));
        }

        try (var fis = new FileInputStream(input); var fos = new FileOutputStream(output)) {
            // Create cipher text
            Cipher cipher = Cipher.getInstance(algorithm + PKCS5_PADDING);

            // Invalid key exception means that they key has a different size than the algorithm result
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm));

            byte[] block = new byte[cipher.getBlockSize()];
            int noBytesWeGot = 0;

            // 0 - eof; -1 after end of file
            while ((noBytesWeGot = fis.read(block)) > 0) {
                // Encrypt current block
                byte[] cipherBlock = cipher.update(block, 0, noBytesWeGot);
                fos.write(cipherBlock);
            }

            // Don't forget the last one
            fos.write(cipher.doFinal());

        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private static void initCipher(Mode mode, Cipher cipher, byte[] key, String algorithm) {
        try {
            switch (mode) {
                case ENC -> cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm));
                case DEC -> cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm));
            }
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private enum Mode {
        ENC,
        DEC
    };
}
