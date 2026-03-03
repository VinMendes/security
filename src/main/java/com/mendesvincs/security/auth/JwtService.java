package com.mendesvincs.security.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class JwtService {

    public static final String CLAIM_TOKEN_TYPE = "token_type";
    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";

    private final Key key;
    private final long accessExpMinutes;
    private final long refreshExpDays;

    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.accessExpMinutes}") long accessExpMinutes,
            @Value("${app.jwt.refreshExpDays}") long refreshExpDays
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpMinutes = accessExpMinutes;
        this.refreshExpDays = refreshExpDays;
    }

    public String generateAccessToken(String username) {
        return generateToken(username, TYPE_ACCESS, Instant.now().plus(accessExpMinutes, ChronoUnit.MINUTES));
    }

    public String generateRefreshToken(String username) {
        return generateToken(username, TYPE_REFRESH, Instant.now().plus(refreshExpDays, ChronoUnit.DAYS));
    }

    private String generateToken(String username, String tokenType, Instant exp) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim(CLAIM_TOKEN_TYPE, tokenType)
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /** Valida assinatura + expiração e devolve Claims (payload). */
    public Claims validateAndGetClaims(String token) {
        return Jwts.parser()
                .verifyWith((javax.crypto.SecretKey) key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Valida e garante que o token é do tipo esperado ("access" ou "refresh"). */
    public Claims validateAndGetClaims(String token, String expectedType) {
        Claims claims = validateAndGetClaims(token);
        String type = claims.get(CLAIM_TOKEN_TYPE, String.class);
        if (!expectedType.equals(type)) {
            throw new IllegalArgumentException("Token type inválido: " + type);
        }
        return claims;
    }
}