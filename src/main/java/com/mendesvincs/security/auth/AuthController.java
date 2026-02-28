package com.mendesvincs.security.auth;

import com.mendesvincs.security.auth.dto.LoginRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller responsável por operações de autenticação da aplicação.
 *
 * <p>
 * Todas as rotas deste controller estão sob o prefixo "/auth".
 * Pela configuração do Spring Security, essas rotas são públicas
 * (permitAll), ou seja, não exigem autenticação prévia.
 * </p>
 *
 * <p>
 * Esse controller é responsável por:
 * <ul>
 *     <li>Receber credenciais do usuário</li>
 *     <li>Validar essas credenciais</li>
 *     <li>Gerar um token JWT</li>
 *     <li>Armazenar o token no cliente via cookie HttpOnly</li>
 *     <li>Permitir logout removendo o cookie</li>
 * </ul>
 * </p>
 *
 * <p>
 * O fluxo de autenticação implementado aqui é baseado em:
 * <strong>JWT + Cookie HttpOnly + Stateless</strong>.
 * Isso significa que o servidor não armazena sessão.
 * O token é validado a cada requisição.
 * </p>
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    /**
     * Serviço responsável por gerar e validar tokens JWT.
     */
    private final JwtService jwtService;

    /**
     * Serviço responsável por manipular cookies de autenticação.
     */
    private final AuthCookieService cookieService;

    /**
     * Injeção de dependências via construtor.
     *
     * @param jwtService serviço de geração/validação de token
     * @param cookieService serviço de manipulação de cookies
     */
    public AuthController(JwtService jwtService, AuthCookieService cookieService) {
        this.jwtService = jwtService;
        this.cookieService = cookieService;
    }

    /**
     * Endpoint responsável por autenticar o usuário.
     *
     * <p>
     * Recebe username e password no corpo da requisição,
     * valida as credenciais e, se estiverem corretas,
     * gera um token JWT e o envia ao cliente via cookie HttpOnly.
     * </p>
     *
     * <p>
     * Importante:
     * Nesta versão, a validação é apenas demonstrativa (hardcoded).
     * Em um cenário real, essa validação seria feita contra um banco
     * de dados utilizando UserDetailsService ou outro mecanismo.
     * </p>
     *
     * @param req objeto contendo username e password enviados pelo cliente
     * @param response objeto HTTP usado para adicionar o cookie na resposta
     * @return 200 OK se autenticado, 401 Unauthorized se inválido
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletResponse response) {

        // Validação simplificada apenas para demonstração
        if (!"vini".equals(req.username()) || !"123".equals(req.password())) {
            return ResponseEntity.status(401).body("Credenciais inválidas");
        }

        // Geração do token JWT contendo o username como subject
        String token = jwtService.generateToken(req.username());

        // Define tempo de vida do cookie (1 hora)
        int maxAgeSeconds = 60 * 60;

        // Armazena o token no cookie HttpOnly
        cookieService.setAuthCookie(response, token, maxAgeSeconds);

        return ResponseEntity.ok("Logado e cookie setado (HttpOnly)");
    }

    /**
     * Endpoint responsável por realizar logout.
     *
     * <p>
     * Como a aplicação é stateless (sem sessão),
     * o logout consiste simplesmente em remover o cookie
     * do cliente.
     * </p>
     *
     * <p>
     * Observação importante:
     * O token JWT em si continua válido até expirar,
     * mas como o cliente não o possui mais, ele não poderá
     * utilizá-lo.
     * </p>
     *
     * @param response objeto HTTP usado para remover o cookie
     * @return mensagem confirmando logout
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        cookieService.clearAuthCookie(response);
        return ResponseEntity.ok("Logout ok (cookie removido)");
    }
}