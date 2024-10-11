package security_study.auth.config;

import io.lettuce.core.RedisURI;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.cache.CacheProperties.Redis;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import security_study.auth.entity.MemberEntity;

@Configuration
@EnableRedisRepositories
@RequiredArgsConstructor
public class RedisConfiguration {

  private final RedisProperties redisProperties;

  /*
   * template -> redis 명령어를 쉽게 사용하게 해준다. ( GET, SET, HSET, DEL ... )
   * */
  @Bean
  public RedisTemplate<String, String> refreshTokenRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
    RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();
    redisTemplate.setConnectionFactory(redisConnectionFactory); // redis 서버의 정보를 입력함.
    redisTemplate.setKeySerializer(new StringRedisSerializer());
    redisTemplate.setValueSerializer(
        new Jackson2JsonRedisSerializer<String>(String.class));
    return redisTemplate;
  }

  @Bean
  public RedisConnectionFactory redisConnectionFactory() {
    RedisURI redisURI = RedisURI.create(redisProperties.getUrl());
    org.springframework.data.redis.connection.RedisConfiguration configuration =
        LettuceConnectionFactory.createRedisConfiguration(redisURI);
    LettuceConnectionFactory factory = new LettuceConnectionFactory(configuration);
    factory.afterPropertiesSet();
    return factory;
  }
}
