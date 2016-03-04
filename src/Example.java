import wrappers.AES_Wrappers;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

/**
 * @author leo.ertuna@gmail.com
 */
public class Example
{
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        String enc = AES_Wrappers.encrypt_256("My Text Example", "paSSword777Example");
        System.out.println(enc);

        String dec = AES_Wrappers.decrypt("ILDfvZw4kODV2t1H/X8bbiUzuNzRiX02CZ/QXpxpP3ppkRdYdfrVSZsdfU4eKbEEmuk16k0quxPO", "paSSword777Example");
        System.out.println(dec);
    }
}
