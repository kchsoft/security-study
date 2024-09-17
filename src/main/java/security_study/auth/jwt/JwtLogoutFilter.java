package security_study.auth.jwt;

import static security_study.auth.constant.JwtConstant.CATEGORY_REFRESH;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.AllArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;
import security_study.auth.repository.RefreshTokenRepository;
import security_study.auth.service.CookieUtil;

@AllArgsConstructor
public class JwtLogoutFilter extends GenericFilterBean {

  private final JwtUtil jwtUtil;
  private final CookieUtil cookieUtil;
  private final RefreshTokenRepository refreshTokenRepository;

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

    // get refresh token
    String refresh = null;
    Cookie[] cookies = request.getCookies();
    for (Cookie cookie : cookies) {

      if (cookie.getName().equals(REFRESH_TOKEN)) {
        refresh = cookie.getValue();
      }
    }

    // refresh null check
    if (refresh == null) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    // expired check
    try {
      jwtUtil.isExpired(refresh);
    } catch (ExpiredJwtException e) {

      // response status code
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
    String category = jwtUtil.getCategory(refresh);
    if (!category.equals(CATEGORY_REFRESH)) {

      // response status code
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    // DB에 저장되어 있는지 확인
    Boolean isExist = refreshTokenRepository.existsByRefreshToken(refresh);
    if (!isExist) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    // 로그아웃 진행
    // Refresh 토큰 DB에서 제거
    refreshTokenRepository.deleteByRefreshToken(refresh);

    // Refresh 토큰 Cookie 값 0
    Cookie invalidate = cookieUtil.invalidate(REFRESH_TOKEN, null);
    response.addCookie(invalidate);
    response.setStatus(HttpServletResponse.SC_OK);
  }
}
