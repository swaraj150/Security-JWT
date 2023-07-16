package com.swaraj.Security.config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor// it will create constructors for private final fields
public class JwtAuthenticationFilter extends OncePerRequestFilter{
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response,@NonNull FilterChain filterChain)throws ServletException,IOException{
        final String authHeader=request.getHeader("Authorization");
        final String jwt;
        // first, lets check if request has jwt token or not
        
        // if (request.getServletPath().contains("/api/v1/auth")) {
        //     filterChain.doFilter(request, response);
        //     return;
        //   }
        System.out.println(authHeader);
        if(authHeader==null){
            System.out.println("jwt");
            filterChain.doFilter(request, response);
            return;
        }
        // if(authHeader==null || !authHeader.startsWith("Bearer ")){
        //     System.out.println("jwt");
        //     filterChain.doFilter(request, response);
        //     return;
        // }
        jwt=authHeader.substring(7);//after Bearer in jwt token
        //lets extract username from token
        final String userEmail;
        userEmail=jwtService.extractUsername(jwt);
        // if username is not null and user is not authenticated
        if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null){
            //check if user exists in our database
            UserDetails userDetails=this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwt, userDetails)){
                //if user is valid we need to update our security context and send request to our dispatcher
                UsernamePasswordAuthenticationToken authtoken=new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                //object credentials as null because while creating a token we dont have credentials;
                authtoken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authtoken);// logged in
            }
        }
        filterChain.doFilter(request, response);//next filters' execution
    }
}
