package com.mendesvincs.security.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AuthCookieService {

    private final String accessCookieName;
    private final String refreshCookieName;
    private final boolean secure;

    public AuthCookieService(
            @Value("${app.cookie.accessName}") String accessCookieName,
            @Value("${app.cookie.refreshName}") String refreshCookieName,
            @Value("${app.cookie.secure}") boolean secure
    ) {
        this.accessCookieName = accessCookieName;
        this.refreshCookieName = refreshCookieName;
        this.secure = secure;
    }

    public void setAccessCookie(HttpServletResponse response, String token, int maxAgeSeconds) {
        response.addCookie(buildCookie(accessCookieName, token, maxAgeSeconds));
    }

    public void setRefreshCookie(HttpServletResponse response, String token, int maxAgeSeconds) {
        response.addCookie(buildCookie(refreshCookieName, token, maxAgeSeconds));
    }

    public void clearAccessCookie(HttpServletResponse response) {
        response.addCookie(buildCookie(accessCookieName, "", 0));
    }

    public void clearRefreshCookie(HttpServletResponse response) {
        response.addCookie(buildCookie(refreshCookieName, "", 0));
    }

    public void clearAuthCookies(HttpServletResponse response) {
        clearAccessCookie(response);
        clearRefreshCookie(response);
    }

    private Cookie buildCookie(String name, String value, int maxAgeSeconds) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAgeSeconds);
        return cookie;
    }

    public String getAccessCookieName() {
        return accessCookieName;
    }

    public String getRefreshCookieName() {
        return refreshCookieName;
    }
}