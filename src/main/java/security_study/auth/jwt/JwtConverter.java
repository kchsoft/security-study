package security_study.auth.jwt;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import security_study.auth.entity.RefreshTokenEntity;
import security_study.auth.jwt.JwtUtil;

@Component
@RequiredArgsConstructor
public class JwtConverter {

  private final JwtUtil jwtUtil;

  public RefreshTokenEntity toRefreshEntity(String refresh) {
    Date expirDate = jwtUtil.getExpiration(refresh);
    LocalDateTime expirTime =
        expirDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

    return RefreshTokenEntity.builder()
        .username(jwtUtil.getUsername(refresh))
        .refreshToken(refresh)
        .expiration(expirTime)
        .build();
  }
}
