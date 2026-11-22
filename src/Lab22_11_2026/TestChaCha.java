package Lab22_11_2026;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class TestChaCha {

    private static final String ALGORITHM = "ChaCha20";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyGenerator kg = KeyGenerator.getInstance("ChaCha20", "BC");
            kg.init(128);
            byte[] chaChaKey = kg.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

        byte[] nounce = new byte[12];
        new SecureRandom().nextBytes(nounce);
    }

    private static byte[] encrypt(String message, byte[] key, byte[] nonce, Mode mode) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key length should be 32");
        } else if (nonce == null || nonce.length != 32) {
            throw new IllegalArgumentException("Nonce length should be 32");
        }

        try {
            Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
            initCipher(mode, cipher, key, ALGORITHM, nonce);
            return cipher.doFinal(message.getBytes());
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException |
                 NoSuchPaddingException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

    }

    private static void initCipher(Mode mode, Cipher cipher, byte[] key, String algorithm, byte[] nonce) {
        try {
            switch (mode) {
                case ENC -> cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm),
                        new ChaCha20ParameterSpec(nonce, 1));
                case DEC -> cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm),
                        new ChaCha20ParameterSpec(nonce, 1));
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
