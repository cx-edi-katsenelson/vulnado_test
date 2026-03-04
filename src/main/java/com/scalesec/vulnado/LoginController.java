package com.scalesec.vulnado;

import org.springframework.web.bind.annotation.*;

@RestController
public class LoginController {

    public static class LoginRequest {
        public String username;
        public String password;
    }

    public static class LoginResponse {
        public boolean success;
        public String message;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest input) {
        User user = User.fetch(input.username);
        LoginResponse response = new LoginResponse();

        if (user == null) {
            response.success = false;
            response.message = "Invalid username or password";
            return response;
        }

        if (user.verifyPassword(input.password)) {
            response.success = true;
            response.message = "Login successful";
        } else {
            response.success = false;
            response.message = "Invalid username or password";
        }

        return response;
    }
}
