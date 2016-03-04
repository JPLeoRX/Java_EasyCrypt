package testers;

import helpers.RandomString;
import junit.framework.Assert;
import org.junit.Test;
import wrappers.AES_Wrappers;

import java.security.SecureRandom;

/**
 * Tester of encryption/decryption methods
 * @author leo.ertuna@gmail.com
 */
public class AES_Test
{
    private static final int NUMBER_OF_TESTS_LARGE = 5000;
    private static int TEXT_LENGTH;
    private static int PASS_LENGTH;

    @Test
    public void testLarge() throws Exception {
        for (int i = 0; i < NUMBER_OF_TESTS_LARGE; i++) {
            TEXT_LENGTH = new SecureRandom().nextInt(4000);                                                             // New random text size
            PASS_LENGTH = new SecureRandom().nextInt(1000);                                                             // New random pass length
            String text = RandomString.next(TEXT_LENGTH);                                                               // New text
            String pass = RandomString.next(PASS_LENGTH);                                                               // New pass
            String enc = AES_Wrappers.encrypt_256(text, pass);                                                          // Encrypted string
            String dec = AES_Wrappers.decrypt(enc, pass);                                                               // Decrypted string
            Assert.assertEquals(text, dec);                                                                             // Make comparison
            System.out.println("N" + i + "\n\t org str: " + text +  "\n\t enc str: " + enc + "\n\t dec str: " + dec);   // Output results
        }
    }
}