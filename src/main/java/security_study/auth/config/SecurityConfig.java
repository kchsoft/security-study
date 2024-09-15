package security_study.auth.config;

import static security_study.auth.constant.AuthoritiesRoleName.ADMIN;
import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;
import security_study.auth.jwt.JWTFilter;
import security_study.auth.jwt.JWTUtil;
import security_study.auth.jwt.JwtAuthenticationFilter;

// jwt - http header O
// jwt - cookie X

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  private final CorsConfigurationSource corsConfigurationSource;
  private final AuthenticationConfiguration authenticationConfiguration;
  private final JWTUtil jwtUtil;
  private final ObjectMapper objectMapper;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable());
    http.cors(
        cors -> cors.configurationSource(corsConfigurationSource)); // security 필터 차원에서의 cors 방지
    http.httpBasic(httpBasic -> httpBasic.disable());
    http.formLogin(formLogin -> formLogin.disable());

    http.authorizeHttpRequests(
        auth ->
            auth.requestMatchers(HttpMethod.GET,"/")
                .permitAll()
                .requestMatchers(HttpMethod.POST,"/join")
                .permitAll()
                .requestMatchers("/member")
                .hasRole(MEMBER)
                .requestMatchers("/admin")
                .hasRole(ADMIN)
                .anyRequest()
                .authenticated());

    http.sessionManagement(
        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    http.addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
    http.addFilterAt(
        new JwtAuthenticationFilter(authenticationManager(authenticationConfiguration), jwtUtil,objectMapper),
        UsernamePasswordAuthenticationFilter.class); // 로그인을 위한 필터이다. 기본적으로 /login 요청이 들어오면 필터가 시작된다.

    return http.build();
  }

  //    @Bean
  //    public UserDetailsService userDetailsService() {
  //        UserDetails user = User.withUsername("user")
  //                .password(passwordEncoder().encode("password"))
  //                .roles("ADMIN")
  //                .build();
  //        return new InMemoryUserDetailsManager(user);
  //    }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
      throws Exception {
    return configuration.getAuthenticationManager();
  }
}
