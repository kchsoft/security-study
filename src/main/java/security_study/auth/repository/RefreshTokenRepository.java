package security_study.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security_study.auth.entity.RefreshTokenEntity;

public interface RefreshTokenRepository
    extends JpaRepository<RefreshTokenEntity, Long>, RefreshTokenRepositoryCustom {

  Boolean existsByRefreshToken(String refresh);

  void deleteByRefreshToken(String refresh);
}
