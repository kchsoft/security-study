package security_study.auth.controller;

import static security_study.auth.constant.JwtConstant.ACCESS_TOKEN_EXPIRATION_TIME;
import static security_study.auth.constant.JwtConstant.CATEGORY_ACCESS;
import static security_study.auth.constant.JwtConstant.CATEGORY_REFRESH;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN_EXPIRATION_TIME;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import security_study.auth.dto.response.LoginResponseDto;
import security_study.auth.entity.RefreshTokenEntity;
import security_study.auth.jwt.JwtConverter;
import security_study.auth.jwt.JwtUtil;
import security_study.auth.repository.RefreshTokenRepository;
import security_study.auth.service.CookieUtil;
import security_study.auth.service.ReissueService;

@RestController
@RequiredArgsConstructor
@Slf4j
public class ReissueController {

  private final JwtUtil jwtUtil;
  private final JwtConverter jwtConverter;
  private final ReissueService reissueService;
  private final CookieUtil cookieUtil;
  private final RefreshTokenRepository refreshTokenRepository;

  @PostMapping("/reissue")
  public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
    // refresh token 유효성 검사
    String refreshToken =
        Optional.ofNullable(request.getCookies())
            .flatMap(
                cookieArray ->
                    Arrays.stream(cookieArray)
                        .filter(cookie -> REFRESH_TOKEN.equals(cookie.getName()))
                        .findFirst()
                        .map(Cookie::getValue))
            .orElse(null);

    // 1. null 검사
    if (refreshToken == null) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("refresh token null");
    }

    // 2. 토큰 기한 검사
    try {
      jwtUtil.isExpired(refreshToken);
    } catch (ExpiredJwtException e) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("refresh token expired");
    }

    // 3. refresh 토큰이 맞는지 확인
    String category = jwtUtil.getCategory(refreshToken);
    if (!CATEGORY_REFRESH.equals(category)) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("category is not refresh token");
    }


    // 4. refresh 이 저장되어 있는지 확인
    if(!refreshTokenRepository.existsByRefreshToken(refreshToken)){
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("refresh token is not stored");
    }

    String username = jwtUtil.getUsername(refreshToken);
    String role = jwtUtil.getRole(refreshToken);

    String newAccessToken =
        jwtUtil.createJwt(CATEGORY_ACCESS, username, role, ACCESS_TOKEN_EXPIRATION_TIME);
    String newRefreshToken =
        jwtUtil.createJwt(CATEGORY_REFRESH, username, role, REFRESH_TOKEN_EXPIRATION_TIME);

    refreshTokenRepository.deleteByRefreshToken(refreshToken);
    RefreshTokenEntity refreshEntity = jwtConverter.toRefreshEntity(refreshToken);
    refreshTokenRepository.save(refreshEntity);

    response.addCookie(cookieUtil.create(REFRESH_TOKEN,newRefreshToken));
    System.out.println("refreshToken = " + refreshToken);
    System.out.println("newRefreshToken = " + newRefreshToken);
    return ResponseEntity.status(HttpStatus.OK)
        .body(
            LoginResponseDto.builder()
                .username(username)
                .accessToken(newAccessToken)
                .isLogin(true)
                .build());
  }
}
