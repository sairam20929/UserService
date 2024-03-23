package com.scaler.userservice.controller;

import com.scaler.userservice.dto.*;
import com.scaler.userservice.model.SessionStatus;
import com.scaler.userservice.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<UserDto> login(@RequestBody LoginRequestDto request) {

        return authService.login(request.getEmail(), request.getPassword());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequestDto request) {

        return authService.logout(request.getToken(), request.getUserId());
    }

    @PostMapping("/signup")
    public ResponseEntity<UserDto> signUp(@RequestBody SignUpRequestDto request) {

        UserDto userDto = authService.signUp(request.getEmail(), request.getPassword());

        return new ResponseEntity<>(userDto, HttpStatus.OK);
    }

    @PostMapping("/validate")
    public ResponseEntity<SessionStatus> validateToken(@RequestBody ValidateTokenRequestDto request) {

        SessionStatus sessionStatus = authService.validate(request.getToken(), request.getUserId());

        if (sessionStatus == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        return new ResponseEntity<>(sessionStatus, HttpStatus.OK);
    }

    @GetMapping("/goto-google")
    public ResponseEntity<Void> redirectToGoogle() {
        return ResponseEntity.status(HttpStatus.FOUND)
                .header("Location", "https://www.google.com") // Replace with desired Google URL
                .build();
    }

}
