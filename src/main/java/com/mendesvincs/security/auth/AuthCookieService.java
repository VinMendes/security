package com.mendesvincs.security.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Serviço responsável por gerenciar o cookie de autenticação da aplicação.
 *
 * <p>
 * Esse serviço encapsula toda a lógica relacionada à criação,
 * configuração e remoção do cookie que armazena o token JWT.
 * </p>
 *
 * <p>
 * A estratégia adotada é:
 * <strong>armazenar o JWT em um cookie HttpOnly</strong>.
 * Isso aumenta a segurança, pois o token não fica acessível via JavaScript
 * (reduzindo risco de XSS).
 * </p>
 *
 * <p>
 * As configurações do cookie (nome e flag secure) são externas
 * e vêm do application.properties:
 * </p>
 *
 * <ul>
 *     <li>app.cookie.name → nome do cookie</li>
 *     <li>app.cookie.secure → define se o cookie só será enviado via HTTPS</li>
 * </ul>
 *
 * <p>
 * Em produção, o ideal é:
 * <ul>
 *     <li>secure = true</li>
 *     <li>usar HTTPS obrigatório</li>
 *     <li>definir SameSite adequadamente</li>
 * </ul>
 * </p>
 */
@Service
public class AuthCookieService {

    /**
     * Nome do cookie que armazenará o token JWT.
     */
    private final String cookieName;

    /**
     * Define se o cookie será enviado apenas via HTTPS.
     * Deve ser true em produção.
     */
    private final boolean secure;

    /**
     * Construtor com injeção de propriedades externas.
     *
     * @param cookieName nome do cookie definido no application.properties
     * @param secure define se o cookie é seguro (HTTPS only)
     */
    public AuthCookieService(
            @Value("${app.cookie.name}") String cookieName,
            @Value("${app.cookie.secure}") boolean secure
    ) {
        this.cookieName = cookieName;
        this.secure = secure;
    }

    /**
     * Cria e adiciona o cookie de autenticação na resposta HTTP.
     *
     * <p>
     * O cookie é configurado com:
     * <ul>
     *     <li>HttpOnly = true → impede acesso via JavaScript</li>
     *     <li>Secure = configurável → apenas HTTPS quando true</li>
     *     <li>Path = "/" → válido para toda aplicação</li>
     *     <li>MaxAge = tempo de vida em segundos</li>
     * </ul>
     * </p>
     *
     * @param response objeto da resposta HTTP
     * @param token token JWT gerado no login
     * @param maxAgeSeconds tempo de vida do cookie em segundos
     */
    public void setAuthCookie(HttpServletResponse response, String token, int maxAgeSeconds) {
        Cookie cookie = new Cookie(cookieName, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAgeSeconds);

        // Observação:
        // SameSite não é configurável diretamente via javax/jakarta Cookie clássico.
        // Caso necessário, pode ser definido manualmente via header "Set-Cookie".
        response.addCookie(cookie);
    }

    /**
     * Remove o cookie de autenticação.
     *
     * <p>
     * A remoção ocorre definindo:
     * <ul>
     *     <li>Valor vazio</li>
     *     <li>MaxAge = 0</li>
     * </ul>
     * </p>
     *
     * <p>
     * Como a aplicação é stateless, não há invalidação de sessão
     * no servidor. O logout consiste apenas em remover o cookie
     * do cliente.
     * </p>
     *
     * @param response objeto da resposta HTTP
     */
    public void clearAuthCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(cookieName, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        cookie.setMaxAge(0);

        response.addCookie(cookie);
    }

    /**
     * Retorna o nome do cookie configurado.
     *
     * <p>
     * Esse método é utilizado pelo filtro de autenticação
     * para localizar o cookie correto na requisição.
     * </p>
     *
     * @return nome do cookie de autenticação
     */
    public String getCookieName() {
        return cookieName;
    }
}