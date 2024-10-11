package security_study.auth.jwt;

import static jakarta.servlet.http.HttpServletResponse.*;
import static java.nio.charset.StandardCharsets.*;
import static org.springframework.http.MediaType.*;
import static security_study.auth.constant.JwtConstant.ACCESS_TOKEN_EXPIRATION_TIME;
import static security_study.auth.constant.JwtConstant.CATEGORY_ACCESS;
import static security_study.auth.constant.JwtConstant.CATEGORY_REFRESH;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN_EXPIRATION_TIME;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import security_study.auth.domain.CustomUserDetails;
import security_study.auth.dto.request.LoginRequestDto;
import security_study.auth.dto.response.LoginResponseDto;
import security_study.auth.repository.RefreshTokenCacheRepository;
import security_study.auth.service.CookieUtil;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final ObjectMapper objectMapper;
  private final RefreshTokenCacheRepository refreshTokenCacheRepository;

  public JwtAuthenticationFilter(
      AuthenticationManager authenticationManager,
      ObjectMapper objectMapper,
      RefreshTokenCacheRepository refreshTokenCacheRepository) {
    this.authenticationManager = authenticationManager;
    this.objectMapper = objectMapper;
    this.refreshTokenCacheRepository = refreshTokenCacheRepository;

    // setFilterProcessesUrl("/api/v1/auth/login"); // 커스텀 login URL을 설정하기
    // default 값은 ("/login") 이다.
  }

  /*

   * login을 시도하면 해당 필터 및 메서드가 실행된다.
   * username, password를 꺼내, 인증 token (username, password 포함)을 만둔 뒤에,
   * auth manager에게 token을 전달하며 인증을 시도한다.
   * */
  @Override
  public Authentication attemptAuthentication(
      HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    try {
      LoginRequestDto requestDto =
          objectMapper.readValue(request.getInputStream(), LoginRequestDto.class);
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
  protected void successfulAuthentication(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain chain,
      Authentication authentication)
      throws IOException {
    CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
    String accessToken = createToken(CATEGORY_ACCESS, userDetails, ACCESS_TOKEN_EXPIRATION_TIME);
    String refreshToken = createToken(CATEGORY_REFRESH, userDetails, REFRESH_TOKEN_EXPIRATION_TIME);
    refreshTokenCacheRepository.save(userDetails.getUsername(), refreshToken);
    setAuthenticationResponse(response, userDetails, accessToken, refreshToken);
    SecurityContextHolder.getContext().setAuthentication(authentication);
  }

  /*
   * 인증에 실패하면 해당 method가 실행된다.
   * http 응답을 작성한다.
   * */
  @Override
  protected void unsuccessfulAuthentication(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
      throws IOException {
    response.setStatus(SC_UNAUTHORIZED);
    response.setContentType(APPLICATION_JSON_VALUE);
    response.setCharacterEncoding(UTF_8.name());

    LoginResponseDto responseDto =
        LoginResponseDto.builder()
            .isLogin(false)
            .username("Authentication failed: " + failed.getMessage())
            .build();

    response.getWriter().write(objectMapper.writeValueAsString(responseDto));
  }

  private UsernamePasswordAuthenticationToken createAuthenticationToken(
      LoginRequestDto requestDto) {
    return new UsernamePasswordAuthenticationToken(
        requestDto.getUsername(), requestDto.getPassword());
  }

  private String createToken(
      String category, CustomUserDetails userDetails, Long tokenExpirationTime) {
    String role = userDetails.getRole();
    return JwtUtil.createJwt(category, userDetails.getUsername(), role, tokenExpirationTime);
  }

  private void setAuthenticationResponse(
      HttpServletResponse response,
      CustomUserDetails userDetails,
      String accessToken,
      String refreshToken)
      throws IOException {
    response.addCookie(CookieUtil.create(REFRESH_TOKEN, refreshToken));
    response.setStatus(SC_OK);
    response.setContentType(APPLICATION_JSON_VALUE);
    response.setCharacterEncoding(UTF_8.name());

    LoginResponseDto responseDto =
        LoginResponseDto.builder()
            .isLogin(true)
            .username(userDetails.getUsername())
            .accessToken(accessToken)
            .build();

    response.getWriter().write(objectMapper.writeValueAsString(responseDto));
  }
}
