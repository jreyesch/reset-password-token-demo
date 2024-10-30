package com.example.reset_password_token_demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class ResetPasswordTokenDemoApplication {
    static Logger logger = LoggerFactory.getLogger(ResetPasswordTokenDemoApplication.class);
    private static final String CRYPTOGRAPHIC_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final String RANDOM_NUMBER_GENERATOR_ALGORITHM = "SHA1PRNG";
    private static final int RADIX = 16;
    private static int ITERATIONS = 600000;
    private static String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static String KEY_SPEC_ALGORITHM = "AES";
    private static int KEY_LENGTH = 256;

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException,
            IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException {
        String email = "testestestestestestestestestestestest@mail.com";
        logger.info("email: {}", email);

        //Generate a Secret Key from a string
        SecretKey secretKey = getSecretKey("P4ssw0rD");

        //Message to bytes
        byte[] encryptedStringAsBytes = encryptString(email.getBytes(), secretKey);
        logger.info("Encrypted: {}", encryptedStringAsBytes);

        //Encrypted bytes to base64
        String base64String = bytesToBase64String(encryptedStringAsBytes);
        logger.info("urlToken: {}", base64String);

        // Base64 string to a safe string to use as a URL param
        String safeURLToken = encodeStringToSafeURL(base64String);
        logger.info("safeURLToken: {}", safeURLToken);

        // Reverse process to get the string URL to its original value
        String decodedSafeURLToken = decodeStringToSafeURL(safeURLToken);
        logger.info("decodedSafeURLToken: {}", decodedSafeURLToken);

        //Base64 String to bytes
        byte[] decodedToken = stringToBytes(decodedSafeURLToken);

        //Bytes to String should show the original value
        String decryptedEmail = new String(decryptMessage(decodedToken, secretKey));
        logger.info("plainTextMessage: {}", decryptedEmail);

        if (email.equals(decryptedEmail)) {
            logger.info("They match !!!");
        }

    }

    private static String encodeStringToSafeURL(String value) throws UnsupportedEncodingException {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
    }

    private static String decodeStringToSafeURL(String value) throws UnsupportedEncodingException {
        return URLDecoder.decode(value, StandardCharsets.UTF_8.toString());
    }

    private static String bytesToBase64String(byte[] bytes) {
        String s = Base64.getEncoder().encodeToString(bytes);
        byte[] decode = Base64.getDecoder().decode(s);
        return s;
    }

    private static byte[] stringToBytes(String s) {
        byte[] decode = Base64.getDecoder().decode(s);
        return decode;
    }

    public static byte[] encryptString(byte[] message, SecretKey secretKey) throws InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedMessage = cipher.doFinal(message);
        return encryptedMessage;
    }

    public static byte[] decryptMessage(byte[] encryptedMessage, SecretKey secretKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] clearMessage = cipher.doFinal(encryptedMessage);
        return clearMessage;
    }

    public static SecretKey getSecretKey(String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(CRYPTOGRAPHIC_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), getRandomSalt(), ITERATIONS, KEY_LENGTH);
        SecretKey originalKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), KEY_SPEC_ALGORITHM);
        return originalKey;
    }

    private static byte[] getRandomSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance(RANDOM_NUMBER_GENERATOR_ALGORITHM);
        byte[] salt = new byte[RADIX];
        sr.nextBytes(salt);
        return salt;
    }
}

