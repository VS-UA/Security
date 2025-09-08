package com.github.detiuaveiro.auth.auth.authenticator.cryptography;

import javax.crypto.SecretKey;
import java.security.Provider;

public class Ratchet {
    private final HKDF keyDerivationFunction;

    private byte[] key;

    public Ratchet(Provider provider, byte[] initializer) {
        this.keyDerivationFunction = new HKDF(provider);
        this.key = initializer;
    }

    public byte[] rotate() {
        final SecretKey key = keyDerivationFunction.createSecretKey(this.key, null);
        this.key = key.getEncoded();
        return keyDerivationFunction.createRandomNumber(key, null, HKDF.ALG_LEN);
    }

    public byte[] restart(byte[] newKey) {
        final SecretKey key = keyDerivationFunction.createSecretKey(newKey, null);
        this.key = key.getEncoded();
        return keyDerivationFunction.createRandomNumber(key, null, HKDF.ALG_LEN);
    }
}
