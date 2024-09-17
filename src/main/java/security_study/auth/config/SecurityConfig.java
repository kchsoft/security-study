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
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfigurationSource;
import security_study.auth.jwt.JwtAuthenticationFilter;
import security_study.auth.jwt.JwtConverter;
import security_study.auth.jwt.JwtFilter;
import security_study.auth.jwt.JwtLogoutFilter;
import security_study.auth.jwt.JwtUtil;
import security_study.auth.repository.RefreshTokenRepository;
import security_study.auth.service.CookieUtil;

// jwt - http header O
// jwt - cookie X

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  private final CorsConfigurationSource corsConfigurationSource;
  private final AuthenticationConfiguration authenticationConfiguration;
  private final JwtUtil jwtUtil;
  private final JwtConverter jwtConverter;
  private final CookieUtil cookieUtil;
  private final ObjectMapper objectMapper;
  private final RefreshTokenRepository refreshTokenRepository;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable());
    http.cors(
        cors -> cors.configurationSource(corsConfigurationSource)); // security 필터 차원에서의 cors 방지
    http.httpBasic(httpBasic -> httpBasic.disable());
    http.formLogin(formLogin -> formLogin.disable()); // UsernamePass..Authen...Filter 를 사용하지 않는다.
    http.logout(logout -> logout.disable()); // logoutFilter를 사용하지 않는다.

    http.authorizeHttpRequests(
        auth ->
            auth.requestMatchers(HttpMethod.GET, "/")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/join", "/reissue")
                .permitAll()
                .requestMatchers("/member")
                .hasRole(MEMBER)
                .requestMatchers("/admin")
                .hasRole(ADMIN)
                .anyRequest()
                .authenticated());

    http.sessionManagement(
        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    http.addFilterBefore(new JwtFilter(jwtUtil), JwtAuthenticationFilter.class);
    http.addFilterAt(
        new JwtAuthenticationFilter(
            authenticationManager(authenticationConfiguration),
            jwtUtil,
            jwtConverter,
            cookieUtil,
            objectMapper,
            refreshTokenRepository),
        UsernamePasswordAuthenticationFilter
            .class); // 로그인을 위한 필터이다. 기본적으로 /login 요청이 들어오면 필터가 시작된다.
    http.addFilterAt(
        new JwtLogoutFilter(jwtUtil, cookieUtil, refreshTokenRepository), LogoutFilter.class);
    return http.build();
  }

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
