package security_study.auth.repository;

import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
@Slf4j
public class BlacklistCacheRepository {
  private final RedisTemplate<String, String> redisTemplate;
  private Duration RT_CACHE_TTL; // = Duration.ofDays(7); // Refresh Token Cache Time To Live

  public BlacklistCacheRepository(
      @Qualifier("blacklistRedisTemplate") RedisTemplate<String, String> redisTemplate,
      @Value("${refresh.token.ttl:P7D}") Duration RT_CACHE_TTL) {
    this.redisTemplate = redisTemplate;
    this.RT_CACHE_TTL = RT_CACHE_TTL;
  }

  public void save(String token, String info) {
    String signature = getSignature(token);
    String key = getKey(signature);
    redisTemplate.opsForValue().set(key, info, RT_CACHE_TTL); // info : username, device, ip and so on...
  }

  public boolean isExist(String token) {
    String signature = getSignature(token);
    String key = getKey(signature);
    return Boolean.TRUE.equals(redisTemplate.hasKey(key));
  }

  private String getKey(String token) {
    return "BLACKLIST:" + token; // key 구성할 때 prefix 붙이는게 좋음. 구별 위해서
  }

  private static String getSignature(String token) {
    int signatureIndex = token.lastIndexOf(".");
    String value = token.substring(signatureIndex);
    log.info("signature value : {}", value);
    return value;
  }
}
