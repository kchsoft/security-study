package security_study.auth.config;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

@TestConfiguration
public class AuthenticationManagerTestConfiguration {

  @Bean
  @Primary
  public AuthenticationManager testAuthenticationManager() {
    AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
    return authenticationManager;
  }

  @Bean
  @Primary
  public AuthenticationConfiguration testAuthenticationConfiguration() throws Exception {
    AuthenticationConfiguration authConfig = mock(AuthenticationConfiguration.class);
    when(authConfig.getAuthenticationManager()).thenReturn(testAuthenticationManager());
    return authConfig;
  }
}
