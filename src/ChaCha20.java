package src;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;

import static src.Utils.*;

import java.nio.ByteBuffer;

public class ChaCha20 {

    private static final String ENCRYPT_ALGO = "ChaCha20";
    private static final int LEN_NONCE = 12;
    private static final int LEN_COUNTER = 4;
    
    /**
     * 
     * @param plaintext
     * @param key
     * @param nonce
     * @param counter
     * @return
     * @throws Exception
     */
    public byte[] encrypt(byte[] plaintext, SecretKey key, byte[] nonce, int counter) 
            throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
        cipher.init(Cipher.ENCRYPT_MODE, key, param);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // append nonce + count
        byte[] result = new byte[ciphertext.length + LEN_NONCE + LEN_COUNTER];
        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
        System.arraycopy(nonce, 0, result, ciphertext.length, LEN_NONCE);

        // convert int to byte[]
        byte[] counterByteArray = ByteBuffer.allocate(4).putInt(counter).array();
        System.arraycopy(counterByteArray, 0, result, ciphertext.length + LEN_NONCE, LEN_COUNTER);

        return result;        
    }

    public byte[] decrypt(byte[] ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        // Parse the input to get the ciphertext, nonce, and counter
        byte[] cText = new byte[ciphertext.length - (LEN_NONCE + LEN_COUNTER)];
        System.arraycopy(ciphertext, 0, cText, 0, ciphertext.length - (LEN_NONCE + LEN_COUNTER));

        byte[] nonce = new byte[12];
        System.arraycopy(ciphertext, cText.length, nonce, 0, LEN_NONCE);

        byte[] counter = new byte[4];
        System.arraycopy(ciphertext, cText.length + LEN_NONCE, counter, 0, LEN_COUNTER);

        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, ByteBuffer.wrap(counter).getInt());
        cipher.init(Cipher.DECRYPT_MODE, key, param);
        
        return cipher.doFinal(cText);        
    }


    public static void main(String[] args) throws Exception {
        String input = "This is a plaintext: demo for ChaCha20 cipher!";

        ChaCha20 cipher = new ChaCha20();
        int keylength = 256;

        SecretKey key = getKey(ENCRYPT_ALGO, keylength);           // 256-bit secret key (32 bytes)
        byte[] nonce = getNonce();                      // 96-bit nonce (12 bytes)
        int counter = 100;                              // 32-bit initial count (8 bytes)

        System.out.println("Input          : " + input);
        System.out.println("Input     (hex): " + convertBytesToHex(input.getBytes()));

        System.out.println("\n---Encryption---");
        byte[] cText = cipher.encrypt(input.getBytes(), key, nonce, counter);  

        System.out.println("Key       (hex): " + convertBytesToHex(key.getEncoded()));
        System.out.println("Nonce     (hex): " + convertBytesToHex(nonce));
        System.out.println("Counter        : " + counter);
        System.out.println("Encrypted (hex): " + convertBytesToHex(cText));

        System.out.println("\n---Decryption---");
        byte[] pText = cipher.decrypt(cText, key);

        System.out.println("Key       (hex): " + convertBytesToHex(key.getEncoded()));
        System.out.println("Nonce     (hex): " + convertBytesToHex(nonce));
        System.out.println("Counter        : " + counter);
        System.out.println("Decrypted (hex): " + convertBytesToHex(pText));
        System.out.println("Decrypted      : " + new String(pText));
    }
}
