package com.fram.workshop.SpringSecurityWorkshop.securityConfig;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;
import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.SignatureAlgorithm;



import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;



@Component
@Log4j2
public class JwtUtils {
    private String jwtSigningKey = "mwas123456789oooooooddfgg";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    private Date extractExpirationDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean hasClaim(String token, String claimName){
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName) != null;
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(jwtSigningKey)
                .parseClaimsJws(token)
                .getBody();
    }



    private boolean isTokenExpired(String token) {
        var expirationDate = extractExpirationDate(token);
        return expirationDate.before(new Date());
    }

//
//    private Key getSignInKey() {
//        byte[]  keyBytes = Decoders.BASE64.decode(jwtSigningKey);
//        return Keys.hmacShaKeyFor(keyBytes);
//    }

    public String generateToken(UserDetails user) {
        return generateToken(user, new HashMap<>());
    }
    public String generateToken(UserDetails user, Map<String, Object> claims) {
        log.info("The claims we have: {}", claims);

        claims.put("authorities", "ROLE_USER");
        claims.put("authorities", "ROLE_ADMIN");
        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(SignatureAlgorithm.HS256, jwtSigningKey)
                .compact()
                ;
    }


    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
}
