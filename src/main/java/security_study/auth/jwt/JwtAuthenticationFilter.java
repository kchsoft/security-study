package security_study.auth.jwt;

import static jakarta.servlet.http.HttpServletResponse.*;
import static java.nio.charset.StandardCharsets.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import javax.print.attribute.standard.Media;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import security_study.auth.domain.CustomUserDetails;
import security_study.auth.dto.request.LoginRequestDto;
import security_study.auth.dto.response.LoginResponseDto;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private static final String BEARER_PREFIX = "Bearer ";
  private static final long TOKEN_VALIDITY = 60 * 60 * 1000L; // 1 hour

  private final AuthenticationManager authenticationManager;
  private final JWTUtil jwtUtil;
  private final ObjectMapper objectMapper;

  public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, ObjectMapper objectMapper) {
    this.authenticationManager = authenticationManager;
    this.jwtUtil = jwtUtil;
    this.objectMapper = objectMapper;
    // setFilterProcessesUrl("/api/v1/auth/login"); // Uncomment to set custom login URL
  }

  /*
  * login을 시도하면 해당 필터 및 메서드가 실행된다.
  * username, password를 꺼내, 인증 token (username, password 포함)을 만둔 뒤에,
  * auth manager에게 token을 전달하며 인증을 시도한다.
  * */
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    try {
      LoginRequestDto requestDto = objectMapper.readValue(request.getInputStream(), LoginRequestDto.class);
      return authenticationManager.authenticate(createAuthenticationToken(requestDto));
    } catch (IOException e) {
      log.error("Failed to process authentication request", e);
      throw new RuntimeException("Authentication process failed", e);
    }
  }

  /*
  * 인증을 성공하면 해당 method가 실행된다.
  * jwt를 만든 뒤에, http 응답을 작성한다.
  * Security Context에도 인증 객체를 설정한다.
  * */
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authentication) throws IOException {
    CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
    String token = createToken(userDetails);

    setAuthenticationResponse(response, userDetails, token);
    SecurityContextHolder.getContext().setAuthentication(authentication);
  }

  /*
  * 인증에 실패하면 해당 method가 실행된다.
  * http 응답을 작성한다.
  * */
  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException {
    response.setStatus(SC_UNAUTHORIZED);
    response.setContentType(APPLICATION_JSON_VALUE);
    response.setCharacterEncoding(UTF_8.name());

    LoginResponseDto responseDto = LoginResponseDto.builder()
        .isLogin(false)
        .username("Authentication failed: " + failed.getMessage())
        .build();

    response.getWriter().write(objectMapper.writeValueAsString(responseDto));
  }

  private UsernamePasswordAuthenticationToken createAuthenticationToken(LoginRequestDto requestDto) {
    return new UsernamePasswordAuthenticationToken(requestDto.getUsername(), requestDto.getPassword());
  }

  private String createToken(CustomUserDetails userDetails) {
    String role = userDetails.getRole();
    return jwtUtil.createJwt(userDetails.getUsername(), role, TOKEN_VALIDITY);
  }

  private void setAuthenticationResponse(HttpServletResponse response, CustomUserDetails userDetails, String token) throws IOException {
    response.addHeader(AUTHORIZATION, BEARER_PREFIX + token);
    response.setStatus(SC_OK);
    response.setContentType(APPLICATION_JSON_VALUE);
    response.setCharacterEncoding(UTF_8.name());

    LoginResponseDto responseDto = LoginResponseDto.builder()
        .isLogin(true)
        .username(userDetails.getUsername())
        .build();

    response.getWriter().write(objectMapper.writeValueAsString(responseDto));
  }
}