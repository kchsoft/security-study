package security_study.auth.jwt;

import static security_study.auth.constant.JwtConstant.CATEGORY_REFRESH;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import security_study.auth.repository.BlacklistCacheRepository;
import security_study.auth.repository.RefreshTokenCacheRepository;
import security_study.auth.service.CookieUtil;

@Slf4j
@AllArgsConstructor
public class JwtLogoutFilter extends GenericFilterBean {

  private final RefreshTokenCacheRepository refreshTokenCacheRepository;
  private final BlacklistCacheRepository blacklistCacheRepository;

  @Override
  public void doFilter(
      ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {
    doFilter(
        (HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse, filterChain);
  }

  private void doFilter(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    // path and method verify
    String requestUri = request.getRequestURI();
    if (!requestUri.matches("^\\/logout$")) {
      filterChain.doFilter(request, response);
      return;
    }

    String requestMethod = request.getMethod();
    if (!requestMethod.equals("POST")) {
      filterChain.doFilter(request, response);
      return;
    }

    // refreshToken은 블랙리스트에 넣는다.
    // get refreshToken
    String refreshToken = null;
    Cookie[] cookies = request.getCookies();
    for (Cookie cookie : cookies) {
      if (cookie.getName().equals(REFRESH_TOKEN)) {
        refreshToken = cookie.getValue();
      }
    }

    // refreshToken null check
    if (refreshToken == null) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    // jjwt 라이브러리가 제공하는 토큰 검증 시행
    try {
      JwtUtil.isValid(refreshToken);
    } catch (JwtException error) {
      log.error(error.getMessage());
      response.setStatus(HttpStatus.BAD_REQUEST.value());
      response.getWriter().write("올바르지 않은 토큰 형식입니다.\n로그아웃에 실패했습니다.");
    }

    // 토큰이 refresh인지 확인
    String category = JwtUtil.getCategory(refreshToken);
    if (!category.equals(CATEGORY_REFRESH)) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      response.getWriter().write("올바르지 않은 토큰 형식입니다.\n로그아웃에 실패했습니다.");
      return;
    }

    // DB에 RT가 저장되어 있는지 확인
    String username = JwtUtil.getUsername(refreshToken);
    Boolean isExist = refreshTokenCacheRepository.isExist(username);
    if (!isExist) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      response.getWriter().write("서비스에 등록되어 있지 않은 토큰 입니다.");
      return;
    }

    // 로그아웃 진행
    // Refresh 토큰 캐쉬에서 제거
    refreshTokenCacheRepository.delete(username);
    // blackList에 Refresh토큰 추가
    blacklistCacheRepository.save(refreshToken, username);

    // Refresh 토큰 Cookie 값 0
    Cookie invalidate = CookieUtil.invalidate(REFRESH_TOKEN, null);
    response.addCookie(invalidate);
    response.setStatus(HttpServletResponse.SC_NO_CONTENT);
  }
}
