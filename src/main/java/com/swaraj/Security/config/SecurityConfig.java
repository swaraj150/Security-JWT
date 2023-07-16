package com.swaraj.Security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)throws Exception{
        http
        .csrf((csrf)->csrf.disable())
        .authorizeHttpRequests((authorize)->authorize
            .requestMatchers("/api/v1/auth/**").permitAll().anyRequest().authenticated()
        )
        .sessionManagement((session)->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authenticationProvider(authenticationProvider)
        .addFilterBefore(jwtAuthenticationFilter,UsernamePasswordAuthenticationFilter.class);
        // .formLogin(formlogin->formlogin
        //     .loginPage("/login").permitAll()
        // )
        // .rememberMe(Customizer.withDefaults());
        // http.oauth2ResourceServer((rs)->rs.jwt(Customizer.withDefaults()));
        return http.build();   
    }
    
}
