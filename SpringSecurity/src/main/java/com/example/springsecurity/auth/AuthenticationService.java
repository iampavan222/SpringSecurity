package com.example.springsecurity.auth;

import com.example.springsecurity.Repository.UserRepository;
import com.example.springsecurity.config.JwtService;
import com.example.springsecurity.entity.Role;
import com.example.springsecurity.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService
{
    private final UserRepository repository;

    private final PasswordEncoder passwordEncoder;

    private  final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request)
    {
       var user= User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

       repository.save(user);

       var jwtToken = jwtService.generateToken(user);
       return  AuthenticationResponse
               .builder()
               .token(jwtToken)
               .build();

    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
      authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(
                      authenticationRequest.getEmail(),
                      authenticationRequest.getPassword()
              )
      );
      var user= repository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
      var jwtToken =jwtService.generateToken(user);
      return AuthenticationResponse
              .builder()
              .token(jwtToken)
              .build();
    }
}
