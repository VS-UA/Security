package com.github.detiuaveiro.auth.auth.authenticator;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import com.github.detiuaveiro.auth.auth.api.objects.Challenge;

import org.json.simple.parser.ParseException;

public interface Authenticator {

    String initAuthenticator(String username, String url) throws ParseException, java.text.ParseException, NoSuchAlgorithmException, InvalidKeySpecException;

    void processChallenge(Challenge challenge) throws NoSuchAlgorithmException, InvalidKeySpecException, java.text.ParseException, ParseException;
}
