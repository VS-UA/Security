package com.github.detiuaveiro.auth.auth;

import com.github.detiuaveiro.auth.auth.authenticator.Authenticator;
import com.github.detiuaveiro.auth.auth.authenticator.PythonAuthenticator;
import com.github.detiuaveiro.auth.auth.db.EncryptionManager;
import com.github.detiuaveiro.auth.auth.db.SQLiteInterface;
import com.github.detiuaveiro.auth.auth.gui.UserInterface;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;

/**
 * Usefull documentation
 * make POST request: https://stackoverflow.com/questions/52609231/get-post-requst-to-rest-api-using-spring-boot
 */
@SpringBootApplication
public class AuthApplication {

    private static final AuthApplication INSTANCE = new AuthApplication();

//    private final Authenticator authenticator = new PBKDF2Authenticator();
    private final Authenticator authenticator = new PythonAuthenticator();
    private final UserInterface userInterface = new UserInterface();

    private EncryptionManager encryptionManager;
    private SQLiteInterface dbInterface;

    public static AuthApplication getInstance() {
        return INSTANCE;
    }

    // TODO: 12/9/21 Fix the singleton
    // Spring needs this constructor for some reason... can't fix it...
//    private AuthApplication() {
//    }

    public static void main(String[] args) {
//        System.out.println(System.getProperty("user.dir"));
//        System.exit(0);

//        System.setProperty("javax.net.ssl.trustStore", "/home/me/Documents/uni/Ano3-Sem1/SIO/projetos/project-2---authentication-equipa_5/auth/cacerts");
//        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        INSTANCE.userInterface.prepareGUI();
        SpringApplication.run(AuthApplication.class);
    }

    public static void setup(String fileName, String dbDecryptor, String entryDecryptor) throws IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        try {
            INSTANCE.encryptionManager = new EncryptionManager(entryDecryptor, dbDecryptor, 16, "AES");
//            try {
//                INSTANCE.encryptionManager.encryptFile(new File("db.db"));
////                INSTANCE.encryptionManager.decryptFile(new File("db.db"));
//                System.exit(0);
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        INSTANCE.dbInterface = new SQLiteInterface(fileName);

//        try { //                          !@#$MySecr3tPassw0rd
//            INSTANCE.dbInterface.addEntry("bananana", "bananaBANANA2021", "35e7841984d35131548d3e0480195767", "localhost");
//            System.exit(0);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public EncryptionManager getEncryptionManager() {
        return encryptionManager;
    }

    public SQLiteInterface getDbInterface() {
        return dbInterface;
    }

    public UserInterface getUserInterface() {
        return userInterface;
    }
}
