package security_study.auth.jwt;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

  private static SecretKey secretKey;
  private static final String CATEGORY = "category";
  private static final String USERNAME = "username";
  private static final String UNIQUE_ID = "unique_id";
  private static final String ROLE = "role";

  private JwtUtil(@Value("${security.jwt.secret}") String secret) {
    this.secretKey =
        new SecretKeySpec(
            secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
  }

  public static void isValid(String token) throws JwtException {
    Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
  }

  public static String getUsername(String token) throws JwtException {

    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token) // 내부적으로 expired 체크함.
        .getPayload()
        .get(USERNAME, String.class);
  }

  public static String getRole(String token) throws JwtException {

    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .get(ROLE, String.class);
  }

  public static String getCategory(String token) throws JwtException {

    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .get(CATEGORY, String.class);
  }

  public static String createJwt(String category, String username, String role, Long expiredMs) {
    Long issuedMs = System.currentTimeMillis();
    String uniqueId = UUID.randomUUID().toString();
    return Jwts.builder()
        .claim(CATEGORY, category)
        .claim(USERNAME, username)
        .claim(UNIQUE_ID, uniqueId)
        .claim(ROLE, role)
        .issuedAt(new Date(issuedMs))
        .expiration(new Date(issuedMs + expiredMs))
        .signWith(secretKey)
        .compact();
  }
}
