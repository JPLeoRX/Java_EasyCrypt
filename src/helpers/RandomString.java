package helpers;

import java.security.SecureRandom;

/**
 * Random String generator used for testing encryption
 * @author leo.ertuna@gmail.com
 */
public abstract class RandomString
{
    private static final String ALPHABET_STRING = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * @param length length of random string
     * @return next random string of a given length
     */
    public static String next(int length)
    {
        StringBuilder stringBuilder = new StringBuilder(length);
        for(int i = 0; i < length; i++)
            stringBuilder.append(ALPHABET_STRING.charAt(SECURE_RANDOM.nextInt(ALPHABET_STRING.length())));
        return stringBuilder.toString();
    }
}
