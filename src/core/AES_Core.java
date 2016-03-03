package core;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;

/**
 * Code modified by <leo.ertuna@gmail.com>
 * Original code by <dweymouth@gmail.com>
 */

/**
 * A class to perform password-based AES encryption and decryption in CBC mode.
 * 128, 192, and 256-bit encryption are supported, provided that the latter two
 * are permitted by the Java runtime's jurisdiction policy files.
 * <br/>
 * The public interface for this class consists of the static methods
 * {@link #encrypt} and {@link #decrypt}, which encrypt and decrypt arbitrary
 * streams of data, respectively.
 */
public abstract class AES_Core
{
    private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";                           // AES specification - changing will break existing encrypted streams!
    private static final String KEYGEN_SPEC = "PBKDF2WithHmacSHA1";                             // Key derivation specification - changing will break existing streams!
    private static final int SALT_LENGTH = 16;                                                  // Size of salt in bytes
    private static final int AUTH_KEY_LENGTH = 8;                                               // Size of key in bytes
    private static final int ITERATIONS = 32768;                                                // Number of iterations
    private static final int BUFFER_SIZE = 1024;                                                // Process input/output streams in chunks - arbitrary



    //------------------------------------------------------------------------------------------------------------------
    //---------------------------------------- Public usable methods ---------------------------------------------------
    //------------------------------------------------------------------------------------------------------------------
    /**
     * Encrypts a stream of data. The encrypted stream consists of a header followed by the raw AES data.
     * @param keyLen                                             key length to use for AES encryption (must be 128, 192, or 256)
     * @param pass                                                  password to use for encryption
     * @param in                                                    an arbitrary byte stream to encrypt
     * @param out                                                   stream to which encrypted data will be written
     * @throws Exceptions.InvalidKeyLengthException                 if keyLength is not 128, 192, or 256
     * @throws Exceptions.StrongEncryptionNotAvailableException     if keyLength is 192 or 256, but the Java runtime's jurisdiction policy files do not allow 192- or 256-bit encryption
     * @throws IOException
     */
    public static void encrypt(int keyLen, char[] pass, InputStream in, OutputStream out) throws Exceptions.InvalidKeyLengthException, Exceptions.StrongEncryptionNotAvailableException, IOException {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) throw new Exceptions.InvalidKeyLengthException(keyLen);    // Check validity of key length
        byte[] salt = generateSalt(SALT_LENGTH);                                                                        // Generate salt
        Keys keys = keygen(keyLen, pass, salt);                                                                         // Derive keys for authentication and encryption

        Cipher encrypt = null; int numRead; byte[] iv = null; byte[] buffer = new byte[BUFFER_SIZE]; byte[] encrypted = null;

        try { encrypt = Cipher.getInstance(CIPHER_SPEC); encrypt.init(Cipher.ENCRYPT_MODE, keys.encryption); }          // Initialize AES encryption
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) { e.printStackTrace(); }                            // Errors occurred
        catch (InvalidKeyException e) { throw new Exceptions.StrongEncryptionNotAvailableException(keyLen); }           // 192 or 256-bit AES not available
        try { iv = encrypt.getParameters().getParameterSpec(IvParameterSpec.class).getIV(); }                           // Get initialization vector
        catch (InvalidParameterSpecException e) { e.printStackTrace(); }                                                // Errors occurred
        out.write(keyLen / 8); out.write(salt); out.write(keys.authentication.getEncoded()); out.write(iv);             // Write authentication and AES initialization data
        while ((numRead = in.read(buffer)) > 0) {                                                                       // Read data from input
            encrypted = encrypt.update(buffer, 0, numRead);                                                             // Encrypt data
            if (encrypted != null) out.write(encrypted); }                                                              // Write to output
        try { encrypted = encrypt.doFinal(); }                                                                          // Finish encryption - do final block
        catch (IllegalBlockSizeException | BadPaddingException e) { e.printStackTrace(); }                              // Errors occurred
        if (encrypted != null) out.write(encrypted);                                                                    // If successful - write output
    }

    /**
     * Decrypts a stream of data that was encrypted by {@link #encrypt}.
     * @param pass                                                      the password used to encrypt/decrypt the stream
     * @param in                                                        stream of encrypted data to be decrypted
     * @param out                                                       stream to which decrypted data will be written
     * @throws Exceptions.InvalidPasswordException                      if the given password was not used to encrypt the data
     * @throws Exceptions.InvalidAESStreamException                     if the given input stream is not a valid AES-encrypted stream
     * @throws Exceptions.StrongEncryptionNotAvailableException         if the stream is 192 or 256-bit encrypted, and the Java runtime's jurisdiction policy files do not allow for AES-192 or 256
     * @throws IOException
     */
    public static void decrypt(char[] pass, InputStream in, OutputStream out) throws Exceptions.InvalidPasswordException, Exceptions.InvalidAESStreamException, IOException, Exceptions.StrongEncryptionNotAvailableException {
        int keyLength = in.read() * 8;                                                                                  // Compute key length
        if (keyLength != 128 && keyLength != 192 && keyLength != 256) throw new Exceptions.InvalidAESStreamException(); // Check validity of key length
        byte[] salt = new byte[SALT_LENGTH]; in.read(salt);                                                             // Read salt
        Keys keys = keygen(keyLength, pass, salt);                                                                      // Generate keys
        byte[] authRead = new byte[AUTH_KEY_LENGTH]; in.read(authRead);                                                 // Generate authenticate password
        if (!Arrays.equals(keys.authentication.getEncoded(), authRead)) throw new Exceptions.InvalidPasswordException();// Check validity of password
        byte[] iv = new byte[16]; in.read(iv);                                                                          // 16-byte I.V. regardless of key size

        Cipher decrypt = null; int numRead; byte[] buffer = new byte[BUFFER_SIZE]; byte[] decrypted;

        try {
            decrypt = Cipher.getInstance(CIPHER_SPEC);                                                                  // Create cipher
            decrypt.init(Cipher.DECRYPT_MODE, keys.encryption, new IvParameterSpec(iv)); }                              // Initialize AES decryption
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) { }            // Errors occurred
        catch (InvalidKeyException e) { throw new Exceptions.StrongEncryptionNotAvailableException(keyLength); }        // 192 or 256-bit AES not available
        while ((numRead = in.read(buffer)) > 0) {                                                                       // Read data from input into buffer
            decrypted = decrypt.update(buffer, 0, numRead);                                                             // Decrypt data
            if (decrypted != null) out.write(decrypted); }                                                              // Write to output
        try {  decrypted = decrypt.doFinal(); }                                                                         // Finish decryption - do final block
        catch (IllegalBlockSizeException | BadPaddingException e) { throw new Exceptions.InvalidAESStreamException(e); }// Errors occurred
        if (decrypted != null) out.write(decrypted);                                                                    // If successful - write output
    }
    //------------------------------------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------------------------------------



    //------------------------------------------------------------------------------------------------------------------
    //------------------------------- Additional tools used by encrypt and decrypt -------------------------------------
    //------------------------------------------------------------------------------------------------------------------
    /**
     * A tuple of encryption and authentication keys returned by {@link #keygen}
     */
    private static class Keys
    {
        public final SecretKey encryption, authentication;

        public Keys(SecretKey encryption, SecretKey authentication) {
            this.encryption = encryption; this.authentication = authentication;
        }
    }

    /**
     * @return a new pseudo-random salt of the specified length
     */
    private static byte[] generateSalt(int length) {
        Random r = new SecureRandom(); byte[] salt = new byte[length]; r.nextBytes(salt); return salt;
    }

    /**
     * Derive an AES encryption key and authentication key from given password and salt, using PBKDF2 key stretching. The authentication key is 64 bits long.
     * @param keyLength             length of the AES key in bits (128, 192, or 256)
     * @param password              the password from which to derive the keys
     * @param salt                  the salt from which to derive the keys
     * @return a Keys object containing the two generated keys
     */
    private static Keys keygen(int keyLength, char[] password, byte[] salt) {
        SecretKeyFactory factory;
        try { factory = SecretKeyFactory.getInstance(KEYGEN_SPEC); }
        catch (NoSuchAlgorithmException impossible) { return null; }

        // derive a longer key, then split into AES key and authentication key
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, keyLength + AUTH_KEY_LENGTH * 8);
        SecretKey tmp = null;
        try { tmp = factory.generateSecret(spec); }
        catch (InvalidKeySpecException impossible) { }
        byte[] fullKey = tmp.getEncoded();
        SecretKey authKey = new SecretKeySpec(Arrays.copyOfRange(fullKey, 0, AUTH_KEY_LENGTH), "AES");                  // key for password authentication
        SecretKey encKey = new SecretKeySpec(Arrays.copyOfRange(fullKey, AUTH_KEY_LENGTH, fullKey.length), "AES");      // key for AES encryption
        return new Keys(encKey, authKey);
    }
    //------------------------------------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------------------------------------
}