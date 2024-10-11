package security_study.auth.controller;

import static security_study.auth.constant.JwtConstant.ACCESS_TOKEN_EXPIRATION_TIME;
import static security_study.auth.constant.JwtConstant.CATEGORY_ACCESS;
import static security_study.auth.constant.JwtConstant.CATEGORY_REFRESH;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN_EXPIRATION_TIME;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
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
import security_study.auth.jwt.JwtUtil;
import security_study.auth.repository.RefreshTokenCacheRepository;
import security_study.auth.service.CookieUtil;
import security_study.auth.service.ReissueService;

@RestController
@RequiredArgsConstructor
@Slf4j
public class ReissueController {

  private final ReissueService reissueService;
  private final RefreshTokenCacheRepository refreshTokenCacheRepository;

  @PostMapping("/reissue")
  public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
    log.info("start refresh token reissue");
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
      log.error("refreshToken is null");
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("refresh token이 없습니다.");
    }
    log.info("token is not null");

    try{
      JwtUtil.isValid(refreshToken); // jjwt 라이브러리가 제공하는 검증 시행
    } catch (ExpiredJwtException expired) {
      log.error(expired.getMessage());
      return ResponseEntity.status(HttpStatus.FOUND).body("토큰이 만료되었습니다.");
    } catch (JwtException error) {
      log.error("jwt exception error");
      log.error(error.getMessage());
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("인증 토큰에 오류가 발생했습니다.");
    }
    log.info("token is valid");

    // 2. refresh 토큰이 맞는지 확인
    String category = JwtUtil.getCategory(refreshToken);
    if (!CATEGORY_REFRESH.equals(category)) {
      log.error("category is not refresh_token");
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("refresh token 형식이 올바르지 않습니다.");
    }
    log.info("token is refresh token");


    // 3. refresh 이 저장되어 있는지 확인
    String username = JwtUtil.getUsername(refreshToken);
    if (!refreshTokenCacheRepository.isExist(username)) {
      log.error("refresh token is not stored");
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("서비스에 없는 refresh token입니다.");
    }
    log.info("cache have refresh token");

    String role = JwtUtil.getRole(refreshToken);
    String newAccessToken =
        JwtUtil.createJwt(CATEGORY_ACCESS, username, role, ACCESS_TOKEN_EXPIRATION_TIME);
    String newRefreshToken =
        JwtUtil.createJwt(CATEGORY_REFRESH, username, role, REFRESH_TOKEN_EXPIRATION_TIME);

    log.info("delete old refresh token = {} - try", refreshToken);
    refreshTokenCacheRepository.delete(username);
    log.info("delete old refresh token = {} - success", refreshToken);

    log.info("add new refresh token = {} - try", newRefreshToken);
    refreshTokenCacheRepository.save(username, newRefreshToken);
    log.info("add new refresh token = {} - success", newRefreshToken);

    response.addCookie(CookieUtil.create(REFRESH_TOKEN, newRefreshToken));
    return ResponseEntity.status(HttpStatus.OK)
        .body(
            LoginResponseDto.builder()
                .username(username)
                .accessToken(newAccessToken)
                .isLogin(true)
                .build());
  }
}
