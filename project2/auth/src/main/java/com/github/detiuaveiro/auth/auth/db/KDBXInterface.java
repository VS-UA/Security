package com.github.detiuaveiro.auth.auth.db;

/*
https://github.com/jorabin/KeePassJava2
 */

import org.linguafranca.pwdb.Credentials;
import org.linguafranca.pwdb.kdbx.KdbxCreds;
import org.linguafranca.pwdb.kdbx.simple.SimpleDatabase;
import org.linguafranca.pwdb.kdbx.simple.SimpleEntry;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KDBXInterface {

    public static final String GROUP_NAME = "AuthApp";

    private final String dbName;

    public KDBXInterface(String dbName) {
        this.dbName = dbName;
    }

    public SimpleDatabase openDB(String credentials) throws Exception {
        final Credentials creds = new KdbxCreds(credentials.getBytes());
        final InputStream inputStream = new FileInputStream(dbName);
        return SimpleDatabase.load(creds, inputStream);
    }

    public List<? extends SimpleEntry> getEntries(String credentials) throws Exception {
        final SimpleDatabase db = openDB(credentials);

        return db.findEntries(entry -> entry.getParent().getName().equals(GROUP_NAME));
    }

    public Map<String, String> getUsernameURLMap(String credentials) throws Exception {
        final Map<String, String> opts = new HashMap<>();

        getEntries(credentials).forEach(e -> opts.put(e.getUsername(), e.getUrl()));

        return opts;
    }

    public String getPassword(String credentials, int pwIndex) throws Exception {
        return getEntries(credentials).get(pwIndex).getPassword();
    }
}
