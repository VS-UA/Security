package com.github.detiuaveiro.auth.auth.db;

import com.github.detiuaveiro.auth.auth.AuthApplication;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.sql.*;
import java.util.*;

/**
 * https://www.tutorialspoint.com/sqlite/sqlite_java.htm
 * https://www.javatpoint.com/java-sqlite
 */
public class SQLiteInterface {

    private final String dbName;

    public SQLiteInterface(String dbName) throws IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        this.dbName = dbName;
//        AuthApplication.getInstance().getEncryptionManager().decryptFile(new File(dbName));
    }

    private Connection connect() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:sqlite:" + dbName);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return conn;
    }

    public Map<String, String> getUsernameURLMap() throws SQLException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        final Map<String, String> opts = new HashMap<>();

        final String query = "SELECT username, url FROM credentials;";

//        AuthApplication.getInstance().getEncryptionManager().decryptFile(new File(dbName));
        final Connection con = connect();
        final ResultSet rs = con.createStatement().executeQuery(query);

        while (rs.next())
            opts.put(decrypt(rs.getString(1)), decrypt(rs.getString(2)));

        con.close();
//        AuthApplication.getInstance().getEncryptionManager().encryptFile(new File(dbName));

        return opts;
    }

    public String getPassword(String name, String url) throws SQLException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        final String query = "SELECT password FROM credentials WHERE username = ? AND url = ?;";

//        AuthApplication.getInstance().getEncryptionManager().decryptFile(new File(dbName));
        final Connection con = connect();
        final PreparedStatement ps = con.prepareStatement(query);

        ps.setString(1, encrypt(name));
        ps.setString(2, encrypt(url));

        final ResultSet rs = ps.executeQuery();
        String passwd = null;
        while (rs.next())
            passwd = decrypt(rs.getString(1));

        con.close();
        ps.close();
//        AuthApplication.getInstance().getEncryptionManager().encryptFile(new File(dbName));

        return passwd;
    }

    public void addEntry(String user, String pass, String otp, String url) throws SQLException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        final String query = "INSERT INTO credentials VALUES (?, ?, ?, ?)";

//        AuthApplication.getInstance().getEncryptionManager().decryptFile(new File(dbName));
        final Connection con = connect();
        final PreparedStatement ps = con.prepareStatement(query);

        ps.setString(1, encrypt(user));
        ps.setString(2, encrypt(pass));
        ps.setString(3, encrypt(otp));
        ps.setString(4, encrypt(url));
//        ps.setString(6, encrypt(String.valueOf(9999)));

        ps.executeUpdate();

        con.close();
        ps.close();
//        AuthApplication.getInstance().getEncryptionManager().encryptFile(new File(dbName));
    }

    public int getPwCnt(String user) throws SQLException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        final String query = "SELECT cnt FROM credentials WHERE user = ?";

//        AuthApplication.getInstance().getEncryptionManager().decryptFile(new File(dbName));
        final Connection con = connect();
        final PreparedStatement ps = con.prepareStatement(query);

        ps.setString(1, encrypt(user));

        final ResultSet rs = ps.executeQuery();
        int cnt = 9999;
        while (rs.next())
            cnt = Integer.parseInt(Objects.requireNonNull(decrypt(rs.getString(1))));

        con.close();
        ps.close();
//        AuthApplication.getInstance().getEncryptionManager().encryptFile(new File(dbName));

        return cnt;
    }

    public int updateCnt(String user) throws SQLException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        final int prev = getPwCnt(user);

        final String query = "UPDATE credentials SET cnt=? WHERE user=?";

//        AuthApplication.getInstance().getEncryptionManager().decryptFile(new File(dbName));
        final Connection con = connect();
        final PreparedStatement ps = con.prepareStatement(query);

        ps.setString(1, encrypt(String.valueOf(prev - 1)));
        ps.setString(2, encrypt(user));

        ps.executeUpdate();

        con.close();
        ps.close();

//        AuthApplication.getInstance().getEncryptionManager().encryptFile(new File(dbName));
        return prev;
    }

    public List<String> getUsers(String url) throws SQLException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
//        final String query = "SELECT user FROM credentials WHERE url = ?";
        final String query = "SELECT username FROM credentials";

//        AuthApplication.getInstance().getEncryptionManager().decryptFile(new File(dbName));
        final Connection con = connect();
        final PreparedStatement ps = con.prepareStatement(query);

//        ps.setString(1, encrypt(url));

        final List<String> res = new ArrayList<>();
        final ResultSet rs = ps.executeQuery();
        while (rs.next())
            res.add(decrypt(rs.getString(1)));

        con.close();
        ps.close();
//        AuthApplication.getInstance().getEncryptionManager().encryptFile(new File(dbName));

        return res;
    }

    private String encrypt(String string) {
        try {
            return Base64.encodeBase64String(AuthApplication.getInstance().getEncryptionManager().encrypt(string));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private String decrypt(String string) {
        try {
            return AuthApplication.getInstance().getEncryptionManager().decrypt(new Base64().decode(string));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String[] getDataForUser(String username, String url) throws SQLException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        final String query = "SELECT username, password, otp, url FROM credentials WHERE username = ? AND url = ?";
//        final String query = "SELECT username FROM credentials";

//        AuthApplication.getInstance().getEncryptionManager().decryptFile(new File(dbName));
        final Connection con = connect();
        final PreparedStatement ps = con.prepareStatement(query);

        System.out.printf("%s, %s\n", username, url);

        ps.setString(1, encrypt(username));
        ps.setString(2, encrypt(url));

        final String[] res = new String[4];
        final ResultSet rs = ps.executeQuery();
        while (rs.next()) {
            res[0] = decrypt(rs.getString(1));
            res[1] = decrypt(rs.getString(2));
            res[2] = decrypt(rs.getString(3));
            res[3] = "https://" + (decrypt(rs.getString(4))) + ":443";
        }

        con.close();
        ps.close();
//        AuthApplication.getInstance().getEncryptionManager().encryptFile(new File(dbName));

        return res;
    }

//    @Override
//    protected void finalize() throws Throwable {
//        AuthApplication.getInstance().getEncryptionManager().encryptFile(new File(dbName));
//        super.finalize();
//    }
}
