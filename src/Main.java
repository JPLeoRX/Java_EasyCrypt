import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Leo on 01-Mar-16.
 */
public class Main
{
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        String enc = AES.encrypt("My Text", "1234_Admin_Leo");
        System.out.println(enc);

        String dec = AES.decrypt(enc, "1234_Admin_Leo");
        System.out.println(dec);
    }


}
