package security_study.auth.jwt;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import security_study.auth.domain.CustomUserDetails;

@Slf4j
public class JwtFilter extends OncePerRequestFilter {

  private static final String BEARER_PREFIX = "Bearer ";
  private final JwtUtil jwtUtil;

  public JwtFilter(JwtUtil jwtUtil) {
    this.jwtUtil = jwtUtil;
  }

  // jwt에서 얻어온 유저가 우리 회원인지 확인 필요 -> DB에서 유저 조회
  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    try {
      String token = extractToken(request);
      if (token != null && jwtUtil.isExpired(token) && isAccessToken(token)) {
        Authentication auth = createAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(auth);
      }
    } catch (ExpiredJwtException e) {
      log.error("JWT is expired", e);
      response.getWriter().write("access token is expired");
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      return;
    } catch (UnsupportedJwtException e){
      log.error(e.getMessage());
      response.getWriter().write(e.getMessage());
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      return;
    }

    filterChain.doFilter(request, response);
  }

  private boolean isAccessToken(String token) {
    String category = jwtUtil.getCategory(token);
    if (!category.equals(AUTHORIZATION))
      throw new UnsupportedJwtException("it is not access token");
    return true;
  }

  private String extractToken(HttpServletRequest request) {
    String authorization = request.getHeader(AUTHORIZATION);
    if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
      return authorization.substring(BEARER_PREFIX.length());
    }
    return null;
  }

  private Authentication createAuthentication(String token) {
    String username = jwtUtil.getUsername(token);
    String role = jwtUtil.getRole(token);
    CustomUserDetails userDetails = CustomUserDetails.builder()
        .username(username)
        .role(role)
        .build();

    return new UsernamePasswordAuthenticationToken(
        userDetails, null, userDetails.getAuthorities());
  }
}