package com.mendesvincs.security.security;

import com.mendesvincs.security.auth.AuthCookieService;
import com.mendesvincs.security.auth.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Filtro de autenticação que lê um JWT vindo de um cookie HttpOnly
 * e transforma isso em uma autenticação válida dentro do Spring Security.
 *
 * <p>
 * Esse filtro é um dos pontos centrais do projeto porque é ele que faz a ponte:
 * </p>
 *
 * <ul>
 *     <li><strong>Cliente</strong> envia cookie com JWT</li>
 *     <li><strong>Servidor</strong> valida o JWT</li>
 *     <li><strong>Spring Security</strong> passa a enxergar o usuário como autenticado</li>
 * </ul>
 *
 * <p>
 * Ele estende {@link OncePerRequestFilter}, garantindo que execute no máximo
 * uma vez por requisição (evita duplicidade em alguns cenários de dispatch).
 * </p>
 *
 * <h2>Fluxo resumido</h2>
 * <ol>
 *     <li>Verifica se já existe autenticação no SecurityContext</li>
 *     <li>Se não existir, procura o cookie de autenticação</li>
 *     <li>Se achar, valida o token JWT</li>
 *     <li>Se for válido, cria um Authentication e salva no SecurityContext</li>
 *     <li>Segue o fluxo chamando {@code filterChain.doFilter()}</li>
 * </ol>
 *
 * <p>
 * Importante: se o token for inválido, o filtro <strong>não bloqueia</strong> diretamente.
 * Ele apenas não autentica e deixa o Spring Security decidir o que fazer
 * (normalmente retornando 401/403 quando a rota exige autenticação).
 * </p>
 */
@Component
public class JwtCookieAuthFilter extends OncePerRequestFilter {

    /**
     * Serviço responsável por validar o JWT e extrair o usuário (subject).
     */
    private final JwtService jwtService;

    /**
     * Serviço responsável por informar o nome do cookie onde o JWT está armazenado.
     */
    private final AuthCookieService cookieService;

    /**
     * Construtor com injeção de dependências.
     *
     * @param jwtService serviço para validação e extração de dados do JWT
     * @param cookieService serviço de utilidades para cookie de autenticação
     */
    public JwtCookieAuthFilter(JwtService jwtService, AuthCookieService cookieService) {
        this.jwtService = jwtService;
        this.cookieService = cookieService;
    }

    /**
     * Método principal do filtro, executado automaticamente a cada requisição.
     *
     * <p>
     * Esse método tenta autenticar o usuário baseado no cookie JWT.
     * Se conseguir, registra a autenticação no {@link SecurityContextHolder},
     * permitindo que endpoints protegidos enxerguem o usuário autenticado.
     * </p>
     *
     * @param request requisição HTTP atual
     * @param response resposta HTTP atual
     * @param filterChain cadeia de filtros do Spring (deve continuar com doFilter)
     * @throws ServletException em caso de erros de servlet
     * @throws IOException em caso de erros de I/O
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        /*
         * Se o usuário já está autenticado no SecurityContext,
         * não precisamos fazer nada. Isso evita reprocessamento.
         */
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        /*
         * Extrai o token do cookie. Se não existir, segue sem autenticar.
         */
        String token = extractTokenFromCookie(request);

        if (token != null) {
            try {
                /*
                 * Valida o token e extrai o subject (username).
                 * Se o token estiver inválido/expirado, isso lança exception.
                 */
                String username = jwtService.validateAndGetSubject(token);

                /*
                 * Cria um Authentication que o Spring Security entende.
                 *
                 * UsernamePasswordAuthenticationToken é um tipo de Authentication
                 * comum no Spring, podendo carregar:
                 * - principal (a identidade: username)
                 * - credentials (senha, normalmente null aqui)
                 * - authorities (roles/permissões)
                 *
                 * Aqui usamos ROLE_USER fixa apenas para demo.
                 * Num cenário real, roles viriam do token (claims) ou do banco.
                 */
                var auth = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
                );

                /*
                 * Registra o usuário como autenticado no contexto do Spring Security.
                 * A partir daqui, o controller consegue receber Authentication e
                 * qualquer @PreAuthorize / regra de segurança passa a funcionar.
                 */
                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (Exception ignored) {
                /*
                 * Se o token for inválido ou expirado:
                 * - limpamos o contexto
                 * - deixamos a requisição seguir sem autenticação
                 *
                 * Se a rota for protegida, o Spring bloqueará depois.
                 */
                SecurityContextHolder.clearContext();
            }
        }

        /*
         * Sempre continue a cadeia de filtros.
         * Se você não chamar isso, a requisição "morre" aqui.
         */
        filterChain.doFilter(request, response);
    }

    /**
     * Extrai o token JWT do cookie de autenticação.
     *
     * <p>
     * O navegador envia cookies automaticamente em requisições para o domínio.
     * Esse método percorre todos os cookies e procura pelo cookie configurado
     * no {@link AuthCookieService}.
     * </p>
     *
     * @param request requisição HTTP atual
     * @return o token JWT (String) se encontrado; caso contrário, null
     */
    private String extractTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;

        String name = cookieService.getCookieName();
        for (Cookie c : cookies) {
            if (name.equals(c.getName()) && c.getValue() != null && !c.getValue().isBlank()) {
                return c.getValue();
            }
        }
        return null;
    }
}