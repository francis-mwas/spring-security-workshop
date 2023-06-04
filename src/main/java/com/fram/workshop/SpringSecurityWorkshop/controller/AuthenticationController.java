package com.fram.workshop.SpringSecurityWorkshop.controller;


import com.fram.workshop.SpringSecurityWorkshop.dao.UserDao;
import com.fram.workshop.SpringSecurityWorkshop.dto.AuthenticationRequest;
import com.fram.workshop.SpringSecurityWorkshop.securityConfig.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Log4j2
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final UserDao userDao;
    private final JwtUtils jwtUtils;

    @PostMapping
    public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequest request){
        log.info("INSIDE THE AUTH CONTROLLER EMAIL: {}",request.getEmail());
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        final UserDetails user = userDao.findUserByEmail(request.getEmail());
        log.info("The user details: {}", user);
        if(user != null){
            return ResponseEntity.ok(jwtUtils.generateToken(user));
        }
        return ResponseEntity.status(400).body("An error occurred");
    }
}
