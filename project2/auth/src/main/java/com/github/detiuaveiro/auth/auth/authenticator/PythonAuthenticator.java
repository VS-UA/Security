package com.github.detiuaveiro.auth.auth.authenticator;

import com.github.detiuaveiro.auth.auth.AuthApplication;
import com.github.detiuaveiro.auth.auth.api.objects.Challenge;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

/**
 * https://www.baeldung.com/java-working-with-python
 * https://www.netjstech.com/2016/10/how-to-run-shell-script-from-java-program.html
 * https://stackoverflow.com/a/55388712
 */
public class PythonAuthenticator implements Authenticator {

//    public static final String MD5SUM = "b86e2fd88e84ac6e6d2dd1f0eebfe1b8";
    public static final String MD5SUM = "79c8f457ee2c9dd9a334e7cc28b0ca3d";
    public static final String MD5SUM_ALT = "7c9ce54936e4e2b67508de76e2d975f0";

    public String code = "";

    @Override
    public String initAuthenticator(String username, String url) {

        //final String scriptPath = "../app_auth/test.py";
        final String scriptPath = "./pythonAuth.py";

        try {
            final File file = new File(scriptPath);
            final MessageDigest mdigest;
            mdigest = MessageDigest.getInstance("MD5");
            final String checksum = AuthApplication.getInstance().getEncryptionManager().checksum(mdigest, file);

            if (!checksum.equals(MD5SUM) && !checksum.equals(MD5SUM_ALT)) {
                System.err.println("Cannot start authenticator, program was tampered with.");
                return "";
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }


        try {
            final String[] data = AuthApplication.getInstance().getDbInterface().getDataForUser(username, url);
            System.out.println(Arrays.toString(data));
            // http://localhost:8080/init_auth?url=localhost
            // py test.py bananana bananaBANANA2021 35e7841984d35131548d3e0480195767 https://localhost:443/
            final ProcessBuilder pb = new ProcessBuilder()
                    .command("../app_auth/authenv/bin/python3.10", "-u", scriptPath,
//                            "bananana", "bananaBANANA2021", "35e7841984d35131548d3e0480195767", "https://localhost:443/");
                            data[0], data[1], data[2], data[3]);

            pb.redirectErrorStream(true);
            System.out.println("Entering script");
            final Process p = pb.start();
            final BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
//            final StringBuilder buffer = new StringBuilder();
            String prevLine = "";
            String line;
            System.out.println("Start");
            StringBuilder buffer = new StringBuilder();
            int cnt = 0;
            while ((line = in.readLine()) != null) {
                buffer.append(line);
                buffer.append('\n');
                prevLine = line;
            }
            System.out.println("DONE!");
            final int exitCode = p.waitFor();
            System.out.println(exitCode);
            System.out.println(buffer);

            if (exitCode == 0)
                AuthApplication.getInstance().getUserInterface().setStatus("Sucess! See the session id in the main page", false, prevLine);
            else
                AuthApplication.getInstance().getUserInterface().setStatus("Error", true);

            in.close();
            System.out.println("LINE: " + prevLine);
            return line;
        } catch (IOException | InterruptedException | SQLException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return "";
    }

    @Override
    public void processChallenge(Challenge challenge) {

    }
}
