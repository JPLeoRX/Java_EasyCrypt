import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;

/**
 * Created by Leo on 01-Mar-16.
 */
public class EncryptionDecryption
{
    //private static String salt;
    private static final int iterations = 65536  ;
    private static final int keySize = 256;
    //private static byte[] ivBytes;
    //private static SecretKey secretKey;

    public static void main(String []args) throws Exception {
        String msg = "Text To Encrypt";
        String pas = "1234";
        String enc = encrypt(msg, pas);
        String dec = decrypt(enc, pas);

        System.out.println("Message: " + msg);
        System.out.println("Encrypted: " + enc);
        System.out.println("Decrypted: " + dec);
    }

    private static String encrypt(String text, String password) throws Exception {
        char[] plaintext = text.toCharArray();

        // Generate secret key
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(text.toCharArray(), password.getBytes(), iterations, keySize);
        SecretKey secretKey = skf.generateSecret(spec);
        SecretKeySpec secretSpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretSpec);
        AlgorithmParameters params = cipher.getParameters();
        byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(String.valueOf(plaintext).getBytes("UTF-8"));

        return DatatypeConverter.printBase64Binary(encryptedTextBytes);
    }

    private static String decrypt(String text, String password) throws Exception {
        byte[] saltBytes = password.getBytes();
        char[] encryptedText = text.toCharArray();
        byte[] encryptedTextBytes = DatatypeConverter.parseBase64Binary(new String(encryptedText));

        // SecretKeySpec secretSpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        // Generate secret key
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(text.toCharArray());
        SecretKey secretKey = skf.generateSecret(spec);
        SecretKeySpec secretSpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        AlgorithmParameters params = cipher.getParameters();
        byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        cipher.init(Cipher.DECRYPT_MODE, secretSpec, new IvParameterSpec(ivBytes));

        byte[] decryptedTextBytes = null;

        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        }   catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }   catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return new String(decryptedTextBytes);

    }

    private static String getSalt() throws Exception
    {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[20];
        sr.nextBytes(salt);
        return new String(salt);
    }
}
