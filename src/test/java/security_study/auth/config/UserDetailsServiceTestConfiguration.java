package security_study.auth.config;

import static org.mockito.Mockito.mock;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetailsService;

@TestConfiguration
public class UserDetailsServiceTestConfiguration {

  @Bean
  @Primary
  public UserDetailsService testUserDetailsService() {
    System.out.println("test config user details service");
    UserDetailsService userDetailsService = mock(UserDetailsService.class);
    return userDetailsService;
  }
}
