package com.beatflow.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/")
    public String root() {
        return "Backend root OK";
    }

    @GetMapping("/api/test")
    public String testApi() {
        return "Backend is running";
    }
}
