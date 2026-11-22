package Lab21_11_20267;

import Lab14_11_2026.TestBitwise;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class TestAESGCM {
    private static final String KEY_ALGORITHM = "AES";
    private static final String ALGORITHM = "AES/GCM/NoPadding";

    public static void main(String[] args) {
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);

        String data = "Send 100 to John";
        String messageTag = "ISM v1";

        // derive using HKDF a new key from the master one
        byte[] key = new byte[32];
        try {
            KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
            kg.init(256);
            key = kg.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        System.out.println("Cipher with AAD tag:");
        var enc = process(data.getBytes(), key, nonce, messageTag, Mode.ENC);
        System.out.println(TestBitwise.getHexString(enc));

        // The destination gets the nonce concatenated with the ciphertext.
        // The destination knows the key and the AAD value.

        System.out.println("\n----------------------------------------------\n");

        System.out.println("Cipher decrypted:");
        var dec = process(enc, key, nonce, messageTag, Mode.DEC);
        System.out.println(new String(dec, StandardCharsets.UTF_8));

        System.out.println("\n----------------------------------------------\n");

        // Test bitflip attack: flip a bit in the ciphertext - flip bit 4 of byte 2 from left (count 0 from left)
//        enc[2] = (byte) (enc[2] ^ (1 << 4));
//        var decrypted = process(enc, key, nonce, messageTag, Mode.DEC);

        // here the client gets a message from a different protocol
        var decrypted = process(enc, key, nonce, "ISM v2", Mode.DEC);

    }

    public static byte[] process(byte[] data, byte[] key, byte[] nonce, String aadValue, Mode mode) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("Key length should be 32");
        } else if (nonce == null || nonce.length != 16) {
            throw new IllegalArgumentException("Nonce length should be 12");
        }

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            initCipher(mode, cipher, key, KEY_ALGORITHM, nonce);

            cipher.updateAAD(aadValue.getBytes());
            return cipher.doFinal(data);
        } catch (AEADBadTagException e) {
            System.out.println("The hacker changed the message.");
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private static void initCipher(Mode mode, Cipher cipher, byte[] key, String algorithm, byte[] nonce) {
        try {
            switch (mode) {
                case ENC -> cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm),
                        new GCMParameterSpec(128, nonce));
                case DEC -> cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm),
                        new GCMParameterSpec(128, nonce));
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private enum Mode {
        ENC,
        DEC
    }
}
