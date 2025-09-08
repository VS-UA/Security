package com.github.detiuaveiro.auth.auth.api.controllers;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/ping")
    @CrossOrigin
    public String testController() {
        return "200";
    }
}
