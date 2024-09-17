package security_study.auth.jwt;

import io.jsonwebtoken.ExpiredJwtException;
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

  private SecretKey secretKey;
  private final String CATEGORY = "category";
  private final String USERNAME = "username";
  private final String UNIQUE_ID = "unique_id";
  private final String ROLE = "role";

  public JwtUtil(@Value("${security.jwt.secret}") String secret) {

    this.secretKey =
        new SecretKeySpec(
            secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
  }

  public String getUsername(String token) {

    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .get(USERNAME, String.class);
  }

  public String getRole(String token) {

    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .get(ROLE, String.class);
  }

  public Boolean isExpired(String token) throws ExpiredJwtException {

    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .getExpiration()
        .before(new Date());
  }

  public String getCategory(String token) {

    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .get(CATEGORY, String.class);
  }

  public Date getExpiration(String token) {
    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .getExpiration();
  }

  public String createJwt(String category, String username, String role, Long expiredMs) {
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
