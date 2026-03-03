package com.mendesvincs.security.auth;

import com.mendesvincs.security.auth.dto.LoginRequest;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtService jwtService;
    private final AuthCookieService cookieService;

    public AuthController(JwtService jwtService, AuthCookieService cookieService) {
        this.jwtService = jwtService;
        this.cookieService = cookieService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletResponse response) {

        if (!"vini".equals(req.username()) || !"123".equals(req.password())) {
            return ResponseEntity.status(401).body("Credenciais inválidas");
        }

        String access = jwtService.generateAccessToken(req.username());
        String refresh = jwtService.generateRefreshToken(req.username());

        int accessMaxAge = 15 * 60;            // 15 min (tem que bater com accessExpMinutes)
        int refreshMaxAge = 7 * 24 * 60 * 60;  // 7 dias (tem que bater com refreshExpDays)

        cookieService.setAccessCookie(response, access, accessMaxAge);
        cookieService.setRefreshCookie(response, refresh, refreshMaxAge);

        return ResponseEntity.ok("Logado: access + refresh cookies setados (HttpOnly)");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {

        String refreshToken = extractCookie(request, cookieService.getRefreshCookieName());
        if (refreshToken == null) {
            return ResponseEntity.status(401).body("Refresh token ausente");
        }

        try {
            Claims claims = jwtService.validateAndGetClaims(refreshToken, JwtService.TYPE_REFRESH);
            String username = claims.getSubject();

            String newAccess = jwtService.generateAccessToken(username);

            int accessMaxAge = 15 * 60;
            cookieService.setAccessCookie(response, newAccess, accessMaxAge);

            return ResponseEntity.ok("Access renovado");
        } catch (Exception e) {
            cookieService.clearAuthCookies(response);
            return ResponseEntity.status(401).body("Refresh inválido/expirado");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        cookieService.clearAuthCookies(response);
        return ResponseEntity.ok("Logout ok (cookies removidos)");
    }

    private String extractCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;

        for (Cookie c : cookies) {
            if (cookieName.equals(c.getName()) && c.getValue() != null && !c.getValue().isBlank()) {
                return c.getValue();
            }
        }
        return null;
    }
}