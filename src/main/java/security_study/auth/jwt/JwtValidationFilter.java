package security_study.auth.jwt;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static security_study.auth.constant.JwtConstant.CATEGORY_ACCESS;

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
public class JwtValidationFilter extends OncePerRequestFilter {

  private static final String BEARER_PREFIX = "Bearer ";

  // jwt에서 식별된 멤버가 우리 회원인지 확인 필요 -> DB에서 멤버 조회
  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String token = extractAccessToken(request);
    if(token == null){
      filterChain.doFilter(request,response);
      return;
    }

    try {
      JwtUtil.isValid(token);
    } catch (ExpiredJwtException e) {
      log.error(e.getMessage());
      response.getWriter().write("access token is expired");
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      return;
    } catch (Exception e) {
      e.printStackTrace();
      log.error(e.getMessage());
      response.getWriter().write("올바르지 않은 토큰입니다.");
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      return;
    }

    log.info("is access token - try");
    if (isAccessToken(token)) {
      Authentication auth = createAuthentication(token);
      SecurityContextHolder.getContext().setAuthentication(auth);
    }
    log.info("is access token - success");

    filterChain.doFilter(request, response);
  }

  private boolean isAccessToken(String token) {
    String category = JwtUtil.getCategory(token);
    if (!category.equals(CATEGORY_ACCESS)) {
      log.error("it is not access token");
      throw new UnsupportedJwtException("access token의 형식이 올바르지 않습니다.");
    }
    return true;
  }

  private String extractAccessToken(HttpServletRequest request) {
    String authorization = request.getHeader(AUTHORIZATION);
    if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
      return authorization.substring(BEARER_PREFIX.length());
    }
    return null;
  }

  private Authentication createAuthentication(String token) {
    String username = JwtUtil.getUsername(token);
    String role = JwtUtil.getRole(token);
    CustomUserDetails userDetails =
        CustomUserDetails.builder().username(username).role(role).build();
    return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
  }
}
