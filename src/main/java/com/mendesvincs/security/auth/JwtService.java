package com.mendesvincs.security.auth;

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

/**
 * Serviço responsável pela criação e validação de tokens JWT (JSON Web Token).
 *
 * <p>
 * O JWT é utilizado para representar a identidade do usuário
 * de forma segura e stateless (sem sessão no servidor).
 * </p>
 *
 * <p>
 * Esse serviço:
 * <ul>
 *     <li>Gera tokens assinados digitalmente</li>
 *     <li>Define tempo de expiração</li>
 *     <li>Valida tokens recebidos do cliente</li>
 *     <li>Extrai informações do token (subject)</li>
 * </ul>
 * </p>
 *
 * <p>
 * O servidor confia no token porque ele é assinado com um segredo
 * conhecido apenas pelo próprio servidor.
 * Se o token for alterado pelo cliente, a assinatura não bate
 * e a validação falha.
 * </p>
 */
@Service
public class JwtService {

    /**
     * Chave criptográfica usada para assinar e validar o token JWT.
     *
     * <p>
     * Essa chave é derivada de um segredo definido no application.properties.
     * Ela é usada em algoritmos HMAC (neste caso, HS256).
     * </p>
     */
    private final Key key;

    /**
     * Tempo de expiração do token, em minutos.
     */
    private final long expMinutes;

    /**
     * Construtor que inicializa a chave criptográfica e o tempo de expiração.
     *
     * @param secret segredo usado para gerar a chave HMAC
     * @param expMinutes tempo de validade do token em minutos
     */
    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expMinutes}") long expMinutes
    ) {
        /*
         * O segredo (string) é convertido em bytes e transformado
         * em uma Key HMAC segura.
         *
         * O tamanho do segredo precisa ser suficiente para o algoritmo HS256,
         * caso contrário a biblioteca lança exceção.
         */
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expMinutes = expMinutes;
    }

    /**
     * Gera um token JWT para um usuário autenticado.
     *
     * <p>
     * O token contém:
     * <ul>
     *     <li>subject → identifica o usuário (username)</li>
     *     <li>issuedAt → data/hora de criação do token</li>
     *     <li>expiration → data/hora de expiração</li>
     * </ul>
     * </p>
     *
     * <p>
     * O token é assinado com HMAC-SHA256 (HS256),
     * garantindo integridade e autenticidade.
     * </p>
     *
     * @param username identificador do usuário autenticado
     * @return token JWT assinado e compactado em formato String
     */
    public String generateToken(String username) {
        Instant now = Instant.now();
        Instant exp = now.plus(expMinutes, ChronoUnit.MINUTES);

        return Jwts.builder()
                .subject(username)                 // identifica o usuário
                .issuedAt(Date.from(now))          // quando o token foi criado
                .expiration(Date.from(exp))        // quando o token expira
                .signWith(key, SignatureAlgorithm.HS256) // assinatura digital
                .compact();
    }

    /**
     * Valida um token JWT e extrai o subject (username).
     *
     * <p>
     * Durante a validação, a biblioteca verifica automaticamente:
     * <ul>
     *     <li>Se a assinatura é válida</li>
     *     <li>Se o token não foi alterado</li>
     *     <li>Se o token não está expirado</li>
     * </ul>
     * </p>
     *
     * <p>
     * Caso o token seja inválido, expirado ou malformado,
     * uma exceção será lançada.
     * </p>
     *
     * @param token token JWT recebido do cliente
     * @return subject (username) contido no token
     */
    public String validateAndGetSubject(String token) {
        return Jwts.parser()
                .verifyWith((javax.crypto.SecretKey) key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}