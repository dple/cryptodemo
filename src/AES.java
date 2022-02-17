package src;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static src.Utils.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AES {
    private static final String ENCRYPT_ALGO = "AES";
    
    /**
     * 
     * @param plaintext
     * @param key
     * @param nonce
     * @param counter
     * @return
     * @throws Exception
     */
    public byte[] encrypt(String algo, byte[] plaintext, SecretKey key, IvParameterSpec iv) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, 
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algo);        
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext);        
    }

    public byte[] decrypt(String algo, byte[] ciphertext, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, 
            BadPaddingException {
        Cipher cipher = Cipher.getInstance(algo);        
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(ciphertext);        
    }


    public static void main(String[] args) throws Exception {
        String input = "This is a plaintext: demo for AES cipher!";
        int keylength = 256;
        String mode = "CBC";
        String pad = "PKCS5Padding";
        String algo = ENCRYPT_ALGO +  "/" + mode + "/" + pad;

        AES cipher = new AES();

        SecretKey key = getKey(ENCRYPT_ALGO, keylength);           // 256-bit secret key (32 bytes)
        IvParameterSpec newIv = newIv();
        
        System.out.println("Input          : " + input);
        System.out.println("Input     (hex): " + convertBytesToHex(input.getBytes()));

        System.out.println("\n---Encryption---");
        byte[] cText = cipher.encrypt(algo, input.getBytes(), key, newIv);   // encrypt

        System.out.println("Key       (hex): " + convertBytesToHex(key.getEncoded()));        
        System.out.println("Encrypted (hex): " + convertBytesToHex(cText));

        System.out.println("\n---Decryption---");
        byte[] pText = cipher.decrypt(algo, cText, key, newIv);              // decrypt

        System.out.println("Key       (hex): " + convertBytesToHex(key.getEncoded()));        
        System.out.println("Decrypted (hex): " + convertBytesToHex(pText));
        System.out.println("Decrypted      : " + new String(pText));        
    }
}
