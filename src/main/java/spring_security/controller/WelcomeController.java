package spring_security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {
    @GetMapping
    public String welcome(){
        return "Welcome to my spring boot web api";
    }
    @GetMapping("/users")
    public String users(){
        return "Authorized users";
    }
    @GetMapping("/managers")
    public String manager(){
        return "Authorized manager";
    }
}
