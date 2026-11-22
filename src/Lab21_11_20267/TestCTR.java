package Lab21_11_20267;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class TestCTR {


    private static final String SEPARATOR = "\\";
    // All reveal the block size because of the padding
    // We have one that is not revealing the block size (cipher text stealing) CTS
    private static final String PKCS5_PADDING = "/CTR/NoPadding";
    private static final String DEFAULT_PATH = "D:\\ASE\\Master\\Anul_I\\Secure Applictions" +
            "\\java\\laboratory\\15.11.2026";

    public static void main(String[] args) {
        // ECB is producing the same encrypted result from the same string always. Data is easier to analyze

        // CBC is using the IV initialization vector, and it is concatenating the plain string block with the last
        // cipher block at each step, meaning same string will produce different encrypted value always
        String key = "password";

        System.out.println("PROCESS");
        process(key.getBytes(), "DES", DEFAULT_PATH + SEPARATOR + "message.txt",
                DEFAULT_PATH + SEPARATOR + "message_ctr.enc", Mode.ENC);
        process(key.getBytes(), "DES", DEFAULT_PATH + SEPARATOR + "message_ctr.enc",
                DEFAULT_PATH + SEPARATOR + "result_ctr.txt", Mode.DEC);

        System.out.println("\n----------------------------------------------\n");

        // Important
        // DES 8 bytes
        // AES 16 bytes
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

            // We decided to generate a random IV and store it in the output file (at the start)
            byte[] IV = new byte[cipher.getBlockSize()];

            // Invalid key exception means that they key has a different size than the algorithm result
            initCipher(mode, cipher, key, algorithm, IV);

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

    private static void initCipher(Mode mode, Cipher cipher, byte[] key, String algorithm, byte[] IV) {
        try {
            switch (mode) {
                case ENC -> cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm),
                        new IvParameterSpec(IV));
                case DEC -> cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm),
                        new IvParameterSpec(IV));
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    // No IV here
//    private static void initIV(Cipher cipher, Mode mode, FileOutputStream fos, FileInputStream fis, byte[] IV) {
//        new SecureRandom().nextBytes(IV);
//        try {
//            switch (mode) {
//                case ENC -> fos.write(IV);
//                case DEC -> fis.read(IV);
//            }
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//    }

    private enum Mode {
        ENC,
        DEC
    }
}
