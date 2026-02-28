package com.apptrack.sdk;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PayloadEncryptor {

    // API key se 32-byte AES key derive karo
    private static byte[] deriveKey(String apiKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(apiKey.getBytes(StandardCharsets.UTF_8));
    }

    // Encrypt JSON payload
    public static String encrypt(String jsonPayload, String apiKey) {
        try {
            byte[] keyBytes = deriveKey(apiKey);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            // Random IV
            byte[] iv = new byte[16];
            new java.security.SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            byte[] encrypted = cipher.doFinal(
                jsonPayload.getBytes(StandardCharsets.UTF_8));

            // IV + encrypted data ko base64 mein encode karo
            byte[] combined = new byte[16 + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, 16);
            System.arraycopy(encrypted, 0, combined, 16, encrypted.length);

            return Base64.encodeToString(combined, Base64.NO_WRAP);
        } catch (Exception e) {
            return null;
        }
    }

    // Decrypt (backend ke liye reference)
    public static String decrypt(String encryptedPayload, String apiKey) {
        try {
            byte[] combined = Base64.decode(encryptedPayload, Base64.NO_WRAP);
            byte[] keyBytes = deriveKey(apiKey);

            byte[] iv        = new byte[16];
            byte[] encrypted = new byte[combined.length - 16];
            System.arraycopy(combined, 0,  iv,        0, 16);
            System.arraycopy(combined, 16, encrypted,  0, encrypted.length);

            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }
}
```

Ab **`EventQueue.java`** mein encrypt karo — request bhejne se pehle:

Pehle dekho `EventQueue.java` ka current code kya hai — share karo ya path batao. Phir wahan encrypt logic add karenge taaki:
```
Plain JSON → AES-256 Encrypt → {"enc":"base64data"} → Server
