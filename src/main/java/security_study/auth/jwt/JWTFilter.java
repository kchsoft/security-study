package security_study.auth.jwt;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import security_study.auth.domain.CustomUserDetails;

@Slf4j
public class JWTFilter extends OncePerRequestFilter {

  private static final String BEARER_PREFIX = "Bearer ";
  private final JWTUtil jwtUtil;

  public JWTFilter(JWTUtil jwtUtil) {
    this.jwtUtil = jwtUtil;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    try {
      String token = extractToken(request);
      if (token != null && isValidToken(token)) {
        Authentication auth = createAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(auth);
      }
    } catch (Exception e) {
      log.error("JWT processing failed", e);
    }

    filterChain.doFilter(request, response);
  }

  private String extractToken(HttpServletRequest request) {
    String authorization = request.getHeader(AUTHORIZATION);
    if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
      return authorization.substring(BEARER_PREFIX.length());
    }
    return null;
  }

  private boolean isValidToken(String token) {
    return !jwtUtil.isExpired(token);
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