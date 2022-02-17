package src;

import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


import org.json.JSONException;
import org.json.JSONObject;

import static src.Utils.*;

public class ECCSignature {
    private static final String CURVE = "secp256r1"; //"secp256k1";
    private static final String KEY_ALGO = "EC";
    private static final String HASHSIGN_ALGO = "SHA256withECDSAinP1363Format"; //"SHA256withECDSA";

    private static byte[] sign(String hashsign_algo, byte[] msg, PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, 
            SignatureException {
        Signature ecSign = Signature.getInstance(hashsign_algo);
        ecSign.initSign(key);
        ecSign.update(msg);
        return ecSign.sign();
    }

    private static boolean verification(String hashsign_algo, byte[] sig, byte[] msg, PublicKey pub) throws NoSuchAlgorithmException, 
            InvalidKeyException, SignatureException {
        Signature ecVerify = Signature.getInstance(hashsign_algo);
        ecVerify.initVerify(pub);
        ecVerify.update(msg);
        return ecVerify.verify(sig);
    }

    private JSONObject sender() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, 
            SignatureException {
        KeyPair keypair = generateECKeypair(KEY_ALGO, CURVE);
        PrivateKey key = keypair.getPrivate();
        PublicKey pub = keypair.getPublic();
        String pubstr = Base64.getEncoder().encodeToString(pub.getEncoded());
        String msg = "This is ECC-based digital signature algorithm!";
        byte[] sig = sign(HASHSIGN_ALGO, msg.getBytes(), key); 
        String signature = Base64.getEncoder().encodeToString(sig);        
        System.out.println("Signature: " + signature);
        System.out.println("Public key: " + pubstr);
        JSONObject obj = new JSONObject();
        obj.put("publicKey", pubstr);
        obj.put("signature", signature);
        obj.put("message", msg);
        obj.put("algorithm", HASHSIGN_ALGO);
        obj.put("keygen", KEY_ALGO);

        return obj;            
    }

    private boolean receiver(JSONObject obj) throws NoSuchAlgorithmException, JSONException, InvalidKeySpecException, 
            InvalidKeyException, SignatureException, UnsupportedEncodingException {
        
        Signature ecVerify = Signature.getInstance(obj.getString("algorithm"));
        KeyFactory  keyFactory = KeyFactory.getInstance(obj.getString("keygen"));
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(obj.getString("publicKey")));
        PublicKey pub = keyFactory.generatePublic(publicKeySpec);
        
        ecVerify.initVerify(pub);
        ecVerify.update(obj.getString("message").getBytes("UTF-8"));

        return ecVerify.verify(Base64.getDecoder().decode(obj.getString("signature")));
    }

    private static void function_test() {
        try {
            KeyPair keypair = generateECKeypair(KEY_ALGO, CURVE);
            PrivateKey key = keypair.getPrivate();
            PublicKey pub = keypair.getPublic();
            String msg = "This is ECC-based digital signature algorithm!";
            
            System.out.println("Input          : " + msg);
            System.out.println("Input     (hex): " + convertBytesToHex(msg.getBytes()));

            System.out.println("\n---Signature Generation---");
            byte[] sig = sign(HASHSIGN_ALGO, msg.getBytes(), key);        
            System.out.println("Signature (hex): " + convertBytesToHex(sig));

            System.out.println("\n---Verification---");

            boolean result = verification(HASHSIGN_ALGO, sig, msg.getBytes(), pub);
            
            System.out.println(result);    
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }

    private static void sign_test() {
        try {
            ECCSignature ecSig = new ECCSignature();
            
            System.out.println("\n---Signature Generation---");
            JSONObject obj = ecSig.sender();

            System.out.println("\n---Verification---");
            boolean result = ecSig.receiver(obj);
            System.out.println(result);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(ECCSignature.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void main(String[] args) {
        
        // Test basic functions
        function_test();
        
        // Test signature generation and verification exchanged through a JSON object
        sign_test();
    }
}
