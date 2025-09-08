package com.github.detiuaveiro.auth.auth.api.objects;

import org.apache.commons.codec.binary.Base64;

import java.security.SecureRandom;

public class Challenge implements APISerializable {
    private final String challenge;
    private final String username;
    private final String sessionID;

    public Challenge() {
        this.challenge = null;
        this.username = null;
        this.sessionID = null;
    }

    public Challenge(String challenge, String username, String sessionID) {
        this.challenge = challenge;
        this.username = username;
        this.sessionID = sessionID;
    }

    /**
     * Generates a random challenge.
     * Use when the validation could not be done so the other party cannot know any further data
     * username and session id must be provided so the other party does not suspect that there was a failure
     *
     * @param username  the user's name
     * @param sessionID the login session's identifier
     */
    public Challenge(String username, String sessionID) {
        this.username = username;
        this.sessionID = sessionID;

        final SecureRandom random = new SecureRandom();
        final byte[] salt = new byte[1];
        random.nextBytes(salt);

        this.challenge = Base64.encodeBase64String(salt);
    }

    public String getChallenge() {
        return challenge;
    }

    public String getSessionID() {
        return sessionID;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public String toAPIMethod() {
        String s = "";

        if ("Hello".equals(challenge)) s += "hello=yo&";
        else if (challenge != null) s += "challenge=" + challenge + "&";
        if (username != null) s += "username=" + username + "&";
        if (sessionID != null) s += "sessionID=" + sessionID + "&";

        return s.substring(0, s.length() - 1);
//        final Map<String, String> map = new HashMap<>();
//
//        if (challenge != null) map.put("challenge", challenge);
//        if (username != null) map.put("username", username);
//        if (sessionID != null) map.put("sessionID", sessionID);
//
//        return map;
    }
}
