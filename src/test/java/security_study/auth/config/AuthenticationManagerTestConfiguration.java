package security_study.auth.config;

import static org.mockito.Mockito.mock;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;

@TestConfiguration
public class AuthenticationManagerTestConfiguration {

  @Bean
  @Primary
  public AuthenticationManager testAuthenticationManager() {

    System.out.println("test config auth manager");
    AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
    return authenticationManager;
  }
}
