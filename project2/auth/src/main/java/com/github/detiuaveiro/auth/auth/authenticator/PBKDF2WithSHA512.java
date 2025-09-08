package com.github.detiuaveiro.auth.auth.authenticator;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.github.detiuaveiro.auth.auth.AuthApplication;
import com.github.detiuaveiro.auth.auth.api.Requests;
import com.github.detiuaveiro.auth.auth.api.objects.Challenge;

public class PBKDF2WithSHA512 implements Authenticator{

    private static final String ALGORITHM = PBKDF2WithSHA512.class.getSimpleName();
    private static final int SIZE = 1024;
    private static final int DEFAULT_COST = 512;
    private final SecureRandom random;
    private static final Pattern layout = Pattern.compile("\\$G\\$(\\d\\d\\d?)\\$(.{512})");
    private static final char[] pepper = "abcdefghijklopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".toCharArray();
    private final int cost;
    private Challenge prev = null;
    private String userName = null;
    private String url = null;
    private boolean isValid;

    public PBKDF2WithSHA512(){
        this.cost = DEFAULT_COST;
        iterations(cost);
        byte[] seed = new byte[512];
        new SecureRandom().nextBytes(seed);
        this.random = new SecureRandom(seed);
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations){
        KeySpec spec = new PBEKeySpec(password, salt, iterations, SIZE);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            System.out.println("Invalid SecretKeyFactory: " + e.getMessage());
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
            System.out.println("No such algorithm: " + ALGORITHM + " : " + e1.getMessage());
        }
        return new byte[1];
    }

    public String hash(String password){
        byte[] salt = new byte[SIZE / 4];
        random.nextBytes(salt);
        char ppr = pepper[random.nextInt(pepper.length)];
        password = password + ppr;
        byte[] dk = pbkdf2(password.toCharArray(), salt, 1 << cost);
        byte[] hash = new byte[salt.length + dk.length];
        System.arraycopy(salt, 0, hash, 0, salt.length);
        System.arraycopy(dk, 0, hash, salt.length, dk.length);
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return cost + enc.encodeToString(hash);
    }

    public boolean auth(String password, String token){
        Matcher m = layout.matcher(token);
        if (!m.matches()){
            throw new IllegalArgumentException("Invalid token");
        }
        int iterations = iterations(Integer.parseInt(m.group(1)));
        byte[] hash = Base64.getUrlDecoder().decode(m.group(2));
        byte[] salt = Arrays.copyOfRange(hash, 0, SIZE / 4);
        for (int i = 0; i < pepper.length; i++){
            char ppr = pepper[i];
            String passw;
            passw = password + ppr;
            byte[] check = pbkdf2(passw.toCharArray(), salt, iterations);
       
            int zero = 0;
            for (int idx = 0; idx < check.length; ++idx){
                  zero |= hash[salt.length + idx] ^ check[idx];
            }
            if (zero == 0) {
                return true;
            }
        }
        return false;
    }

    private static int iterations(int cost){
        if ((cost & ~0x200) != 0) {
            throw new IllegalArgumentException("cost: " + cost);
        }
        return 1 << cost;
    }

    @Override
    public String initAuthenticator(String username, String url) throws org.json.simple.parser.ParseException, ParseException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (prev != null)
            return "";

        final Challenge c = new Challenge("Hello", userName, null);

        this.userName = userName;
        this.url = url;

        try {
            processChallenge(Requests.sendChallenge(c));
        } catch (IOException e) {
            e.printStackTrace();
        }

        return "";
    }

    @Override
    public void processChallenge(Challenge challenge) throws NoSuchAlgorithmException, InvalidKeySpecException, ParseException, org.json.simple.parser.ParseException {
        prev = challenge;

        try {
            final String password = AuthApplication.getInstance().getDbInterface().getPassword(userName, url);
            final String validate = hash(password);

            if (!validate.equals(challenge.getChallenge()))
                isValid = false;

            String otp = "";

            int pwCnt = AuthApplication.getInstance().getDbInterface().updateCnt(userName);
            for (int i = pwCnt; i-- > 0; otp = hash(otp)) ;

            final Challenge ch = isValid ?
                    new Challenge(
                            hash(password).substring(0, 8),
                            userName, prev.getSessionID()
                    ) :
                    new Challenge(userName, prev.getSessionID());

            Requests.sendChallenge(ch);

            prev = ch;
        } catch (SQLException | IOException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

}