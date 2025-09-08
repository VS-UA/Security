package com.github.detiuaveiro.auth.auth.api.controllers;

import com.github.detiuaveiro.auth.auth.AuthApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.sql.SQLException;

@RestController
public class InitAuthProcess {

    @GetMapping("/init_auth")
    public RedirectView initAuth(@RequestParam(value = "url") String url) {
//        AuthApplication.getInstance().getAuthenticator().initAuthenticator(input.getUserName(), input.getUrl());

//        AuthApplication.getInstance().getUserInterface().setStatus("Yeet", false);
        try {
            /*final String sessionID = */AuthApplication.getInstance().getUserInterface().showResults(url);

            //        return new RedirectView("https://" + url + ":443");

//            while (AuthApplication.getInstance().getUserInterface().getSessionID() == null);

//            final String sessionID = AuthApplication.getInstance().getUserInterface().getSessionID();
//            final String redirect = "https://" + url + ":443" + "/e-login?sessionID=" + sessionID;
            final String redirect = "https://" + url + ":443" + "/e-login";
            System.out.println(redirect);
            return new RedirectView(redirect);
        } catch (SQLException | BadPaddingException | IllegalBlockSizeException | IOException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return new RedirectView("https://google.com");
    }
}