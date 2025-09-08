package com.github.detiuaveiro.auth.auth.authenticator;

import com.github.detiuaveiro.auth.auth.api.Requests;
import com.github.detiuaveiro.auth.auth.api.objects.Challenge;
import com.github.detiuaveiro.auth.auth.authenticator.cryptography.HKDF;
import com.github.detiuaveiro.auth.auth.authenticator.cryptography.Ratchet;
import org.json.simple.parser.ParseException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * https://www.geeksforgeeks.org/cryptographic-hash-function-in-java/
 */
public class DoubleRatchetAuthenticator implements Authenticator {

    public static final int OVERFLOW = 2 * HKDF.ALG_LEN;

    private final Provider provider;

    private final Ratchet main;
    private final Ratchet pass;
    private final Ratchet otp;
    private final Ratchet rule;

    private String userName;
    private String url;

    public DoubleRatchetAuthenticator(Provider p, byte[] init, String userName, String url) {
        this.userName = userName;
        this.url = url;
        provider = p;

        main = new Ratchet(p, init);

        final byte[] passInit = main.rotate();
        final byte[] otpInit = main.rotate();
        final byte[] ruleInit = main.rotate();

        pass = new Ratchet(p, passInit);
        otp = new Ratchet(p, otpInit);
        rule = new Ratchet(p, ruleInit);
    }

    @Override
    public String initAuthenticator(String userName, String url) {
        final Challenge c = new Challenge("Hello", userName, null);

        this.userName = userName;
        this.url = url;

        try {
            Requests.sendChallenge(c);
        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }

        return "";
    }

    @Override
    public void processChallenge(Challenge challenge) {

        //====================
        //  HASH
        //====================
        final ByteArrayOutputStream byte_Stream = new ByteArrayOutputStream();

//        byte_Stream.write(salt);
        try {
            byte_Stream.write(otp.rotate());
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] valueToHash = byte_Stream.toByteArray();
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        final byte[] encIn = messageDigest.digest(valueToHash);

        //====================
        //  ENCRYPT
        //====================

        //====================
        //  PARSE
        //====================

        // TODO: 12/25/21 There is probably a better way of getting an int out of this
        final int rule = new BigInteger(this.rule.rotate()).mod(BigInteger.valueOf(HKDF.ALG_LEN + OVERFLOW)).hashCode();

        final byte challText = encIn[rule];

        //====================
        //  SEND
        //====================

        try {
            Requests.sendChallenge(new Challenge(String.valueOf(challText), userName, null));
        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }
    }

    private byte[] reinitialize(byte[] newKey) {
        byte[] newMasterKey = main.restart(newKey);

        pass.restart(main.rotate());
        otp.restart(main.rotate());
        rule.restart(main.rotate());

        return newMasterKey;
    }
}
