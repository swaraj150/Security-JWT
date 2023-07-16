package com.swaraj.Security.config;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.HashMap;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.util.Map;
import java.util.function.Function;
@Service
public class JwtService{
    private static final String SECRET_KEY="RHWcIbU0TsuQce5Tvx6wI8aim8kFgQM3l1C2wmEH99BGpEB7fsYXNClms3dD8q9OVUinEmAjypJXLkJJxJnq8/DtdbaaFHN/50WMTp9O1s0FyFYDuUQwatuKRvHwAoO9PYElKmFJkSZYacijS9CB/oIpwB+o3KcMqn7y1tU9J9uGMRcaGzGD4ZGmj0FyobNaEllblmgmqb5Vaxm3AyjZIHbbg6euPaSG3pVroo7SZM6mghuPYemOh7h/tMDqMi8xtIM3/znZjpvmSe+M7hDx1gA4v/bPUFdErcEk++N0j6j4VBxg3QYdSkqXOzOG6ObZNNGigxY8fd2Y0/cjpt8cWlnjTjricJcZNBPsRn99Fbk=";
    
    private SecretKey getSigningKey(){
        byte[] keyBytes=Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    public <T> T extractClaim(String jwt,Function<Claims,T> claimsResolver){
        final Claims claims=extractAllClaims(jwt);
        return claimsResolver.apply(claims);

    }
    public String extractUsername(String jwt){
        return extractClaim(jwt,Claims::getSubject);
    }
    private Claims extractAllClaims(String jwt){
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(jwt).getBody();
    }
    public String generateToken(Map<String,Object> extraClaims,UserDetails userDetails){
        
        return Jwts
        .builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
        .signWith(getSigningKey(),SignatureAlgorithm.HS256)
        .compact();
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
        
    }

    //check validity of token
    public boolean isTokenValid(String jwt,UserDetails userDetails){
        final String username=extractUsername(jwt);
        return !isTokenExpired(jwt) && username.equals(userDetails.getUsername());
    }
    private boolean isTokenExpired(String jwt){
        return extractExpiration(jwt).before(new Date());
    }
    private Date extractExpiration(String jwt){
        return extractClaim(jwt, Claims::getExpiration);
    }
}