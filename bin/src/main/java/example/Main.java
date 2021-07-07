package example;

import org.apache.commons.codec.binary.Hex;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * This is the Main class.
 */
public class Main {

    private static final String SALT = "abc123";

    private static final int iterations = 10000;
    private static final int keyLength = 512;

    public static void main(String[] args) throws UnsupportedEncodingException {

        String plainText = "Hello World!";
        String stored = hashPsw(plainText);
        boolean isMatch = checkPsw(plainText, stored);

        System.out.println("Original: " + plainText);
        System.out.println("Hash: " + stored);
        System.out.println("Verified: " + isMatch);
    }

    private static String hashPsw(String plainText) {
        return hashPassword(plainText);
    }
    private static boolean checkPsw(String plainText, String hashedStr) {
        String stored = hashPsw(plainText);
        return stored.equals(hashedStr);
    }

    private static String hashPassword( final String plainText ) {

      char[] passwordChars = plainText.toCharArray();
      byte[] saltBytes = SALT.getBytes();
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
            PBEKeySpec spec = new PBEKeySpec( passwordChars, saltBytes, iterations, keyLength );
            SecretKey key = skf.generateSecret( spec );
            byte[] res = key.getEncoded( );
            return Hex.encodeHexString(res);
        } catch ( NoSuchAlgorithmException | InvalidKeySpecException e ) {
            throw new RuntimeException( e );
        }
    }
}
