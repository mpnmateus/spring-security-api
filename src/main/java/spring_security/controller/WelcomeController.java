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
    @PreAuthorize("hasAnyRole('MANAGERS', 'USERS')")
    public String users(){
        return "Authorized users";
    }
    @GetMapping("/managers")
    @PreAuthorize("hasAnyRole('MANAGERS')")
    public String manager(){
        return "Authorized manager";
    }
}
