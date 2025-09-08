package com.github.detiuaveiro.auth.auth.authenticator.cryptography;


import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Provider;

/**
 * Based on https://github.com/patrickfav/hkdf/
 */
public class HKDF {
    public static final String ALG_NAME = "HmacSHA512";
    public static final int ALG_LEN = 512;

    private final Provider provider;


    public HKDF(Provider provider) {
        this.provider = provider;
    }

    public SecretKey createSecretKey(byte[] generatorKey, SecretKey salt) {
        if (generatorKey == null || generatorKey.length <= 0) {
            throw new IllegalArgumentException("provided generatorKey must be at least of size 1 and not null");
        }

        final Mac mac = createMac(salt, provider);
        return new SecretKeySpec(mac.doFinal(generatorKey), ALG_NAME);
    }

    public byte[] createRandomNumber(SecretKey pseudoRandomKey, byte[] info, int outLengthBytes) {
        if (outLengthBytes <= 0)
            throw new IllegalArgumentException("out length bytes must be at least 1");

        if (pseudoRandomKey == null)
            throw new IllegalArgumentException("provided pseudoRandomKey must not be null");

        final Mac hmacHasher = createMac(pseudoRandomKey, provider);

        if (info == null)
            info = new byte[0];

        byte[] blockN = new byte[0];

        int iterations = (int) Math.ceil(((double) outLengthBytes) / ((double) hmacHasher.getMacLength()));

        if (iterations > 255)
            throw new IllegalArgumentException("out length must be maximal 255 * hash-length; requested: " + outLengthBytes + " bytes");

        final ByteBuffer buffer = ByteBuffer.allocate(outLengthBytes);
        int remainingBytes = outLengthBytes;
        int stepSize;

        for (int i = 0; i < iterations; i++) {
            hmacHasher.update(blockN);
            hmacHasher.update(info);
            hmacHasher.update((byte) (i + 1));

            blockN = hmacHasher.doFinal();

            stepSize = Math.min(remainingBytes, blockN.length);

            buffer.put(blockN, 0, stepSize);
            remainingBytes -= stepSize;
        }

        return buffer.array();
    }

    private Mac createMac(SecretKey key, Provider provider) {
        try {
            Mac mac = provider == null ?
                    Mac.getInstance(ALG_NAME) :
                    Mac.getInstance(ALG_NAME, provider);
            mac.init(key);
            return mac;
        } catch (Exception e) {
            throw new IllegalStateException("could not make hmac hasher in hkdf", e);
        }
    }
}
