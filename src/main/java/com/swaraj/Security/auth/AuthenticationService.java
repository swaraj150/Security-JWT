package com.swaraj.Security.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.swaraj.Security.config.JwtService;
import com.swaraj.Security.user.Role;
import com.swaraj.Security.user.User;
import com.swaraj.Security.user.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.var;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

   
    public AuthenticationResponse register(RegisterRequest request){
        var user=User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(Role.User)
        .build();
        
        userRepository.save(user);
        var jwtToken=jwtService.generateToken(user);
        return AuthenticationResponse.builder()
        .token(jwtToken)
        .msg("Registration Succesful")
        .build();
    }
    public AuthenticationResponse authenticate(AuthenticationRequest request){
        try {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword());
            System.out.println(authenticationToken.getCredentials());
            authenticationManager.authenticate(authenticationToken);
            
        } catch (BadCredentialsException b) {
            System.out.println("hello");
            return AuthenticationResponse.builder().msg("Invalid Credentials").build();
            // throw new BadCredentialsException("Incorrect username or password", b);
        }
        var user=userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken=jwtService.generateToken(user);
        return AuthenticationResponse.builder()
            .token(jwtToken)
            .msg("Login Successful")
            .build();
    }
}
