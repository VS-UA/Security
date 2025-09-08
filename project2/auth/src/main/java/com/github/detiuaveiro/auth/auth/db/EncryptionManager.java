package com.github.detiuaveiro.auth.auth.db;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * https://mkyong.com/java/java-symmetric-key-cryptography-example/
 * https://stackoverflow.com/questions/4487525/encrypt-and-decrypt-a-string-in-java
 */
public class EncryptionManager {
    private final SecretKeySpec entrySecretKey;
    private final SecretKeySpec dbSecretKey;
    private final Cipher cipher;

    public EncryptionManager(String entryDecryptor, String dbDecryptor, int length, String algorithm)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {

        byte[] key = fixSecret(entryDecryptor, length);
        this.entrySecretKey = new SecretKeySpec(key, algorithm);

        key = fixSecret(dbDecryptor, length);
        this.dbSecretKey = new SecretKeySpec(key, algorithm);

        this.cipher = Cipher.getInstance(algorithm);
    }

    private byte[] fixSecret(String s, int length) {
        final StringBuilder sBuilder = new StringBuilder(s);

        for (int i = sBuilder.length(); i < length; i++)
            sBuilder.append(" ");
        s = sBuilder.toString();

        return s.substring(0, length).getBytes(StandardCharsets.UTF_8);
    }

    public void encryptFile(File f)
            throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.ENCRYPT_MODE, this.entrySecretKey);
        this.writeToFile(f);
    }

    public void decryptFile(File f)
            throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, this.entrySecretKey);
        this.writeToFile(f);
    }

    private int writeToFile(File f) throws IOException, IllegalBlockSizeException, BadPaddingException {
        final InputStream in = new FileInputStream(f);
        byte[] input = new byte[(int) f.length()];
        final int status = in.read(input);

        final OutputStream out = new FileOutputStream(f);
        final byte[] output = this.cipher.doFinal(input);
        out.write(output);

        out.flush();
        out.close();
        in.close();

        return status;
    }

    public byte[] encrypt(String s) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        this.cipher.init(Cipher.ENCRYPT_MODE, this.entrySecretKey);
        byte[] input = s.getBytes(StandardCharsets.UTF_8);

        return this.cipher.doFinal(input);
    }

    public String decrypt(byte[] bytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, this.entrySecretKey);

        byte[] decipher = this.cipher.doFinal(bytes);

        return new String(decipher, StandardCharsets.UTF_8);
    }

    /**
     * https://www.geeksforgeeks.org/how-to-generate-md5-checksum-for-files-in-java/
     *
     * @param digest
     * @param file
     * @return
     * @throws IOException
     */
    public String checksum(MessageDigest digest, File file) throws IOException {
        final FileInputStream fis = new FileInputStream(file);

        final byte[] byteArray = new byte[1024];

        int bytesCount;
        while ((bytesCount = fis.read(byteArray)) != -1) {
            digest.update(byteArray, 0, bytesCount);
        }
        fis.close();

        final byte[] bytes = digest.digest();

        final StringBuilder sb = new StringBuilder();

        for (byte aByte : bytes) {
            sb.append(Integer
                    .toString((aByte & 0xff) + 0x100, 16)
                    .substring(1));
        }

        return sb.toString();
    }

//    public byte[] toHex(String s) {
//        // https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
//        if (s.length() % 2 != 0)
//            s = "0" + s;
//
//        final int len = s.length();
//        byte[] data = new byte[len / 2];
//        for (int i = 0; i < len; i += 2) {
//            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
//                    + Character.digit(s.charAt(i+1), 16));
//        }
//        return data;
//    }
}
