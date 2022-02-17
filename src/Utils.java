package src;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class Utils {
    
    /**
     * Initialization Vector (IV) that has the same size as the block that is encrypted. 
     * We can use the SecureRandom class to generate a random IV.
     * 
     * @return IvParameterSec
     */
    public static IvParameterSpec newIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
    * Get a 256-bit secret key (32 bytes)
    * @return
    * @throws NoSuchAlgorithmException
    */
   public static SecretKey getKey(String algo, int keylength) throws NoSuchAlgorithmException {
       KeyGenerator keyGen = KeyGenerator.getInstance(algo);
       keyGen.init(keylength, SecureRandom.getInstanceStrong());       
       return keyGen.generateKey();
   }

   /**
    * Get a 96-bit nonce (12 bytes)
    * @return
    */
   public static byte[] getNonce() {
       byte[] newNonce = new byte[12];
       new SecureRandom().nextBytes(newNonce);
       return newNonce;
   }

   /**
    * Convert bytes to Hex
    * @param bytes
    * @return
    */
   public static String convertBytesToHex(byte[] bytes) {
       StringBuilder result = new StringBuilder();
       for (byte temp : bytes) {
           result.append(String.format("%02x", temp));
       }
       return result.toString();
   }

   /**
    * Get a keypair of ECDSA
    *
    * @param curve
    * @return
 * @throws NoSuchAlgorithmException
 * @throws InvalidAlgorithmParameterException
    */
   public static KeyPair generateECKeypair(String keyalgo, String curve) throws NoSuchAlgorithmException, 
            InvalidAlgorithmParameterException {
       ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);
       KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyalgo);
       keyGen.initialize(ecSpec, SecureRandom.getInstanceStrong());
       return keyGen.generateKeyPair();
   }

}
