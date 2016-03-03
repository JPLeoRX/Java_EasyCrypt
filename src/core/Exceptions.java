package core;

/**
 * Exceptions used in AES encryption/decryption process
 * @author leo.ertuna@gmail.com
 * @author dweymouth@gmail.com
 */
public class Exceptions
{
    /**
     * Thrown if an attempt is made to decrypt an invalid AES stream.
     */
    public static class InvalidAESStreamException extends Exception
    {
        public InvalidAESStreamException() {
            super();
        }

        public InvalidAESStreamException(Exception e) {
            super(e);
        }
    }

    /**
     * Thrown if 192- or 256-bit AES encryption or decryption is attempted,
     * but not available on the particular Java platform.
     */
    public static class StrongEncryptionNotAvailableException extends Exception
    {
        public StrongEncryptionNotAvailableException(int keySize) {
            super(keySize + "-bit AES encryption is not available on this Java platform.");
        }
    }

    /**
     * Thrown if an attempt is made to encrypt a stream with an invalid AES key length.
     */
    public static class InvalidKeyLengthException extends Exception
    {
        InvalidKeyLengthException(int length) {
            super("Invalid AES key length: " + length);
        }
    }

    /**
     * Thrown if an attempt is made to decrypt a stream with an incorrect password.
     */
    public static class InvalidPasswordException extends Exception
    {

    }
}
