package security_study.auth.repository;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import security_study.auth.entity.RefreshTokenEntity;
import security_study.auth.jwt.JwtUtil;

@RequiredArgsConstructor
public class RefreshTokenRepositoryCustomImpl implements RefreshTokenRepositoryCustom {

  private final JwtUtil jwtUtil;

  public Optional<RefreshTokenEntity> save(String refresh) {
    return Optional.empty();
  }


}
