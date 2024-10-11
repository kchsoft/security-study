package security_study.auth.repository;

import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
@Slf4j
public class RefreshTokenCacheRepository {

  private final RedisTemplate<String, String> redisTemplate;
  private Duration RT_CACHE_TTL; // = Duration.ofDays(7); // Refresh Token Cache Time To Live

  public RefreshTokenCacheRepository(
      @Qualifier("refreshTokenRedisTemplate") RedisTemplate<String, String> redisTemplate,
      @Value("${refresh.token.ttl:P7D}") Duration RT_CACHE_TTL) {
    this.redisTemplate = redisTemplate;
    this.RT_CACHE_TTL = RT_CACHE_TTL;
  }

  public void save(String username, String token) {
    String key = getKey(username);
    redisTemplate.opsForValue().set(key, token, RT_CACHE_TTL);
  }

  public String get(String username) {
    String key = getKey(username);
    return redisTemplate.opsForValue().get(key);
  }

  public boolean delete(String username) {
    String key = getKey(username);
    return Boolean.TRUE.equals(redisTemplate.delete(key));
  }

  public boolean isExist(String username) {
    String key = getKey(username);
    return Boolean.TRUE.equals(redisTemplate.hasKey(key));
  }

  private String getKey(String username) {
    return "REFRESH:" + username; // key 구설할 때 prefix 붙이는게 좋음. 구별 위해서
  }
}
