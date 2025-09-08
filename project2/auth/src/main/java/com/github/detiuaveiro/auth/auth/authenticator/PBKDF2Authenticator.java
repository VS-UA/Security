package com.github.detiuaveiro.auth.auth.authenticator;

import com.github.detiuaveiro.auth.auth.AuthApplication;
import com.github.detiuaveiro.auth.auth.api.Requests;
import com.github.detiuaveiro.auth.auth.api.objects.Challenge;
import org.json.simple.parser.ParseException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.SQLException;
import java.util.Arrays;

/**
 * Based on <a href=https://gist.github.com/jtan189/3804290>this gist</a>
 */
public class PBKDF2Authenticator implements Authenticator {

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";
    public static final int SALT_BYTES = 24;
    public static final int HASH_BYTES = 24;
    public static final int PBKDF2_ITERATIONS = 1000;
    private static final int KEY_LENGTH = 64;

    private Challenge prev = null;
    private String userName = null;
    private String url = null;

    private boolean isValid;

    @Override
    public String initAuthenticator(String userName, String url) {
        if (prev != null)
            return "";

        final Challenge c = new Challenge("Hello", userName, null);

        this.userName = userName;
        this.url = url;

        try {
            processChallenge(Requests.sendChallenge(c));
        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }

        return "";
    }

    @Override
    public void processChallenge(Challenge challenge) {
        prev = challenge;

        try {
            final String password = AuthApplication.getInstance().getDbInterface().getPassword(userName, url);
            final String validate = hash(password,
                    challenge.getSessionID() + prev);

            if (!validate.equals(challenge.getChallenge()))
                isValid = false;

            // TODO: 12/24/21 Get this from somewhere, salt too
            String otp = "";

            int pwCnt = AuthApplication.getInstance().getDbInterface().updateCnt(userName);
            for (int i = pwCnt; i-- > 0; otp = hash(otp, "static salt")) ;

            final Challenge ch = isValid ?
                    new Challenge(
                            hash(password,
                                    challenge.getSessionID() + prev + otp).substring(0, 8),
                            userName, prev.getSessionID()
                    ) :
                    new Challenge(userName, prev.getSessionID());

            Requests.sendChallenge(ch);

            prev = ch;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | SQLException | IOException | ParseException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private String hash(String password, String saltString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final byte[] salt;
        if (saltString == null) {
            // Generate a random salt
            final SecureRandom random = new SecureRandom();
            salt = salt();
            random.nextBytes(salt);
        } else {
            salt = saltString.getBytes(StandardCharsets.UTF_8);
        }

        // Hash the password
        final byte[] hash = pbkdf2(password.toCharArray(), salt);
        return toHex(hash);
    }

    public static byte[] hash(final String password, final byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		final KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH);
		final SecretKeyFactory secretKeyfactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
		return secretKeyfactory.generateSecret(keySpec).getEncoded();
	}

    private byte[] pbkdf2(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, HASH_BYTES * 8);
        final SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return skf.generateSecret(spec).getEncoded();
    }

    private String toHex(byte[] array) {
        final String hex = new BigInteger(1, array).toString(16);
        final int paddingLength = (array.length * 2) - hex.length();

        return paddingLength > 0 ?
                String.format("%0" + paddingLength + "d", 0) + hex :
                hex;
    }

    private String fromHex(String s) {
        if (s.length() % 2 != 0)
            s = "0" + s;

        byte[] binary = new byte[s.length() / 2];
        for (int i = 0; i < binary.length; i++) {
            binary[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }

        return Arrays.toString(binary);
    }

    public static byte[] salt() throws NoSuchAlgorithmException {
		final byte[] salt = new byte[16];
		SecureRandom.getInstance("SHA1PRNG").nextBytes(salt);
		return salt;
	}

    public static String convertToString(final byte[] payload) {
		String result = "";
		for (byte b : payload) {
			result += b + " ";
		}
		return result.trim();
	}

    public static byte[] toByteArray(final String s) {
		final String[] arr = s.split(" ");
		final byte[] b = new byte[arr.length];
		for (int i = 0; i < arr.length; i++) {
			b[i] = Byte.parseByte(arr[i]);
		}
		return b;
	}

    public static boolean authenticate(final String attemptedPassword, final byte[] salt, final byte[] hashedPassword) throws Exception {
		return Arrays.equals(hash(attemptedPassword, salt), hashedPassword);
	}
}
