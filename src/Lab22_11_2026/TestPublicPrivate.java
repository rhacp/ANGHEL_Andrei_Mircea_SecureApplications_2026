package Lab22_11_2026;

import Lab14_11_2026.TestBitwise;

import javax.crypto.*;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Enumeration;

public class TestPublicPrivate {

    private static final String ALIAS = "ismkey1";
    private static final String ALIAS_ISM = "ismasero";
    private static final String STORE_PASSWORD = "passks";
    private static final String KEYSTORE = "ismkeystore.ks";
//    private static final String ALGORITHM = "RSA/ECB/PKCS1.1";
    private static final String ALGORITHM = "RSA/ECB/OAEPPadding";

    public static void main(String[] args) {
        KeyStore ks = loadKeyStore(KEYSTORE, STORE_PASSWORD);
        listKeyStore(ks);

        System.out.println("\n-------------------------------------\n");

//        System.out.println("Alias: ");
//        Scanner sc = new Scanner(System.in);
//        String alias = sc.nextLine();

        System.out.println("\nPublic-Private key: ");
        System.out.println("PUB: " + TestBitwise.getHexString(getPublicKey(ks, ALIAS).getEncoded()));
        System.out.println("PRV: " + TestBitwise.getHexString(getPrivateKey(ks, ALIAS, STORE_PASSWORD)
                .getEncoded()));

        System.out.println("\n-------------------------------------\n");

        String certificateFile = "ISMCertificateX509.cer";
        System.out.println("Certificate key: " + TestBitwise.getHexString(getCertificateKey(certificateFile)
                .getEncoded()));
        System.out.println("Certificate key: " + TestBitwise.getHexString(getCertificateKey("ism.ase.ro.crt")
                .getEncoded()));
        System.out.println("Check keyyyyyyy: " + TestBitwise.getHexString(getPublicKey(ks, ALIAS_ISM)
                .getEncoded()));

        System.out.println("\n-------------------------------------\n");

        // simulate AES random key distribution using RSA
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // Not working because of Oracle
//        keyGenerator.init(512);
        keyGenerator.init(256);
        byte[] aesKey = keyGenerator.generateKey().getEncoded();
        System.out.println("AES Key: " + TestBitwise.getHexString(aesKey));

        // encrypt AES key with destination public key
        var publicKey = getPublicKey(ks, ALIAS);
        var privateKey = getPrivateKey(ks, ALIAS, STORE_PASSWORD);
        byte[] encryptedAESKey = processRSA(aesKey, publicKey, Mode.ENC);
        byte[] decryptedAESKey = processRSA(encryptedAESKey, privateKey, Mode.DEC);
        System.out.println("EncryptedAESKey: " + TestBitwise.getHexString(encryptedAESKey));
        System.out.println("DecryptedAESKey: " + TestBitwise.getHexString(decryptedAESKey));

        System.out.println("\n-------------------------------------\n");

        // test digital signature
        byte[] signature = signFile("message.txt", privateKey);
        System.out.println("Signature: " + TestBitwise.getHexString(signature));

        // the destinatio will decrypt with its own key
        System.out.println(checkFileSignature("message.txt", publicKey, signature));
        System.out.println(checkFileSignature("message2.txt", publicKey, signature));
    }

    private static KeyStore loadKeyStore(String filename, String password) {
        File file = new File(filename);

        if (!file.exists()) {
            throw new IllegalArgumentException("KeyStore file does not exist");
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(fis, password.toCharArray());
            return ks;
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static void listKeyStore(KeyStore ks) {
        if (ks == null) {
            throw new IllegalArgumentException("KeyStore is null");
        }
        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String item = aliases.nextElement();
                System.out.println("Entry: " + item);
                if (ks.isCertificateEntry(item)) {
                    System.out.println("Type: public certificate");
                } else if (ks.isKeyEntry(item)) {
                    System.out.println("Type: private:public key");
                }
                System.out.println("\n----------------\n");
            }
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey getPublicKey(KeyStore ks, String alias) {
        if (ks == null) {
            throw new IllegalArgumentException("KeyStore is null");
        }

        try {
            if (ks.containsAlias(alias)) {
                return ks.getCertificate(alias).getPublicKey();
            } else {
                throw new IllegalArgumentException("KeyStore does not contain alias: " + alias);
            }
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    private static PrivateKey getPrivateKey(KeyStore ks, String alias, String password) {
        if (ks == null) {
            throw new IllegalArgumentException("KeyStore is null");
        }

        try {
            if (ks.containsAlias(alias) && ks.isKeyEntry(alias)) {
                return (PrivateKey) ks.getKey(alias, password.toCharArray());
            } else {
                throw new IllegalArgumentException("KeyStore does not contain alias: " + alias);
            }
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey getCertificateKey(String certificateFile) {
        File file = new File(certificateFile);
        if (!file.exists()) {
            throw new IllegalArgumentException("Certificate file does not exist");
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(fis);
            return certificate.getPublicKey();
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] processRSA(byte[] data, Key key, Mode mode) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            initCipher(mode, cipher, key);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] signFile(String fileName, PrivateKey key) {
        Path filePath = Paths.get(fileName);
        if (!Files.exists(filePath)) {
            throw new IllegalArgumentException("File does not exist");
        }

        try {
            var content = Files.readAllBytes(filePath);
            Signature signature = Signature.getInstance("SHA256withRSA");
            initSignature(SignMode.SIGN, signature, key);
            signature.update(content);
            return signature.sign();

        } catch (IOException | NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean checkFileSignature(String fileName, PublicKey key, byte[] signatureBytes) {
        Path filePath = Paths.get(fileName);
        if (!Files.exists(filePath)) {
            throw new IllegalArgumentException("File does not exist");
        }

        try {
            var content = Files.readAllBytes(filePath);
            Signature signature = Signature.getInstance("SHA256withRSA");
            initSignature(SignMode.CHECK, signature, key);
            signature.update(content);
            return signature.verify(signatureBytes);

        } catch (IOException | NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private static void initSignature(SignMode mode, Signature signature, Key key) {
        try {
            switch (mode) {
                case SignMode.SIGN -> signature.initSign((PrivateKey) key);
                case SignMode.CHECK -> signature.initVerify((PublicKey) key);
            }
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static void initCipher(Mode mode, Cipher cipher, Key key) {
        try {
            switch (mode) {
                case ENC -> cipher.init(Cipher.ENCRYPT_MODE, key, new OAEPParameterSpec("SHA-256",
                        "MGF1", MGF1ParameterSpec.SHA3_256, PSource.PSpecified.DEFAULT));
                case DEC -> cipher.init(Cipher.DECRYPT_MODE, key, new OAEPParameterSpec("SHA-256",
                        "MGF1", MGF1ParameterSpec.SHA3_256, PSource.PSpecified.DEFAULT));
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private enum Mode {
        ENC,
        DEC
    }

    private enum SignMode {
        SIGN,
        CHECK
    }
}
