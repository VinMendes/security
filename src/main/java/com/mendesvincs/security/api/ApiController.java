package com.mendesvincs.security.api;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Controller responsável por expor endpoints protegidos da aplicação.
 *
 * <p>
 * Todas as rotas definidas aqui estão sob o prefixo "/api".
 * Pela configuração do Spring Security, qualquer rota que não esteja em "/auth/**"
 * exige autenticação. Isso significa que, para acessar "/api/ping",
 * o usuário precisa estar autenticado com um token válido.
 * </p>
 *
 * <p>
 * A autenticação é realizada por meio de um filtro personalizado
 * (JwtCookieAuthFilter), que intercepta a requisição, extrai o token
 * armazenado no cookie, valida o JWT e, se for válido, popula o
 * SecurityContext com um objeto Authentication.
 * </p>
 *
 * <p>
 * Quando o método do controller recebe um parâmetro do tipo
 * {@link org.springframework.security.core.Authentication},
 * o Spring injeta automaticamente o usuário autenticado atual,
 * com base no SecurityContext.
 * </p>
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    /**
     * Endpoint simples para simular uma rota protegida da aplicação.
     *
     * <p>
     * Esse método só será executado se o usuário estiver autenticado.
     * Caso contrário, o Spring Security bloqueará a requisição
     * antes mesmo de chegar aqui.
     * </p>
     *
     * <p>
     * O objeto {@link Authentication} representa o usuário autenticado.
     * Ele contém:
     * <ul>
     *     <li>O principal (normalmente o username)</li>
     *     <li>As authorities (roles/permissões)</li>
     *     <li>Informações adicionais da autenticação</li>
     * </ul>
     * </p>
     *
     * @param auth Objeto que representa o usuário autenticado atual,
     *             injetado automaticamente pelo Spring Security.
     * @return Uma string confirmando que o usuário está autenticado,
     *         exibindo o nome do usuário extraído do token.
     */
    @GetMapping("/ping")
    public String ping(Authentication auth) {
        return "pong ✅ | user=" + auth.getName();
    }
}