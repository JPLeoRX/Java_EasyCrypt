package wrappers;

import core.AES_Core;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Base64;

/**
 * Wrappers of AES core methods
 * They will allow simple encryption of strings with password
 * Tested with strings up to 4 000 characters and passwords up to 1 000 characters
 * @author leo.ertuna@gmail.com
 */
public class AES_Wrappers
{
    /**
     * Encrypt a string using a password
     * @param text                                          data to encrypt
     * @param password                                      encryption password
     * @return an encrypted data
     */
    public static String encrypt(String text, String password) {
        InputStream inputStream; ByteArrayOutputStream outputStream; String result = null;                              // Initialize temporary variables

        try {
            inputStream = IOUtils.toInputStream(text, "UTF-8");                                                         // Convert text to input stream
            outputStream = new ByteArrayOutputStream();                                                                 // Create new output stream
            AES_Core.encrypt(256, password.toCharArray(), inputStream, outputStream);                                   // Encrypt data
            result = Base64.getEncoder().encodeToString(outputStream.toByteArray());                                    // Get string from output stream
            inputStream.close(); outputStream.close();                                                                  // Close both streams
        }

        catch (Exception e) { e.printStackTrace(); }                                                                    // If errors occurred
        return result;                                                                                                  // Return string
    }

    /**
     * Decrypt a string using a password
     * @param encryptedText                                 data to decrypt
     * @param password                                      decryption password
     * @return a decrypted data
     */
    public static String decrypt(String encryptedText, String password) {
        ByteArrayInputStream inputStream; ByteArrayOutputStream outputStream; String result = null;                     // Initialize temporary variables

        try {
            inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(encryptedText));                          // Convert encrypted string to input stream
            outputStream = new ByteArrayOutputStream();                                                                 // Create new output stream
            AES_Core.decrypt(password.toCharArray(), inputStream, outputStream);                                        // Decrypt data
            result = outputStream.toString("UTF-8");                                                                    // Get string from output stream
            inputStream.close(); outputStream.close();                                                                  // Close both streams
        }

        catch (Exception e) { e.printStackTrace(); }                                                                    // If errors occurred
        return result;                                                                                                  // Return string
    }
}