package security_study.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static security_study.auth.config.MemberInfoConstant.RAW_PASSWORD_TEST;
import static security_study.auth.config.MemberInfoConstant.USERNAME_TEST;
import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;
import static security_study.auth.constant.AuthoritiesRoleName.ROLE_;
import static security_study.auth.constant.JwtConstant.CATEGORY_REFRESH;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN_EXPIRATION_TIME;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import security_study.auth.domain.CustomUserDetails;
import security_study.auth.dto.request.LoginRequestDto;
import security_study.auth.listener.ContextCreationListener;
import security_study.auth.repository.RefreshTokenCacheRepository;
import security_study.auth.service.CookieUtil;

@SpringBootTest
@AutoConfigureMockMvc
@Slf4j
@TestExecutionListeners(
    listeners = ContextCreationListener.class,
    mergeMode = MergeMode.MERGE_WITH_DEFAULTS)
@TestPropertySource(properties = "refresh.token.ttl=PT1S") // redis의 duration을 1초로 지정함.
public class JwtRefreshTokenCacheTest {

  @Autowired private ObjectMapper objectMapper;
  @Autowired private MockMvc mockMvc;
  @Autowired private RefreshTokenCacheRepository refreshTokenCacheRepository;

  @MockBean private AuthenticationManager mockAuthenticationManager;

  @Mock UserDetails dbMemberDetails;

  private final String CACHE_PREFIX = "CACHE_";
  private final String CACHE_USERNAME = CACHE_PREFIX + USERNAME_TEST;
  private final String CACHE_PASSWORD = CACHE_PREFIX + RAW_PASSWORD_TEST;

  @BeforeEach
  void setup() {
    dbMemberDetails =
        CustomUserDetails.builder()
            .username(CACHE_USERNAME)
            .password(CACHE_PASSWORD)
            .role(ROLE_ + MEMBER)
            .build();

    Authentication authentication = mock(Authentication.class);
    when(authentication.getPrincipal()).thenReturn(dbMemberDetails);

    when(mockAuthenticationManager.authenticate(any())).thenReturn(authentication);
  }

  @AfterEach
  void cleanup() {
    refreshTokenCacheRepository.delete(CACHE_USERNAME);
  }

  @Test
  @DisplayName("로그인 -> 발급된 RT는 Cache에 저장")
  void loginSaveRtToCache() throws Exception {
    LoginRequestDto loginRequest =
        LoginRequestDto.builder().username(CACHE_USERNAME).password(CACHE_PASSWORD).build();
    MvcResult result =
        mockMvc
            .perform(
                post("/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        objectMapper.writeValueAsString(loginRequest))) // 객체를 json 형태(string)로 변환
            .andExpect(status().isOk())
            .andDo(print())
            .andReturn();

    MockHttpServletResponse response = result.getResponse();
    Cookie cookie = response.getCookie(REFRESH_TOKEN);
    assertThat(cookie).isNotNull();
    String refreshToken = cookie.getValue();
    assertThat(refreshToken).isNotNull().isNotBlank();
    assertThat(JwtUtil.getCategory(refreshToken))
        .as("Refresh Token이 아닙니다.")
        .isEqualTo(CATEGORY_REFRESH);
    assertThat(JwtUtil.getUsername(refreshToken))
        .as("입력한 유저 ID와 JWT 클레임의 유저 ID가 서로 다릅니다.")
        .isEqualTo(CACHE_USERNAME);
    assertThat(JwtUtil.getRole(refreshToken))
        .as("사용자의 ROLE과 JWT 클레임의 ROLE이 서로 다릅니다.")
        .isEqualTo(ROLE_ + MEMBER);
    assertThat(cookie.isHttpOnly()).as("쿠키에 HttpOnly가 True로 설정되지 않았습니다.").isTrue();
    assertThat(refreshToken).isEqualTo(refreshTokenCacheRepository.get(CACHE_USERNAME));
  }

  @Test
  @DisplayName("RT -> reissue uri 접근 -> Cache에 기존 RT 제거 및 새로운 RT 저장")
  void reissueRefreshToken() throws Exception {
    String beforeRefresh =
        JwtUtil.createJwt(
            CATEGORY_REFRESH, CACHE_USERNAME, ROLE_ + MEMBER, REFRESH_TOKEN_EXPIRATION_TIME);
    refreshTokenCacheRepository.save(CACHE_USERNAME, beforeRefresh);

    MvcResult mvcResult =
        mockMvc
            .perform(post("/reissue").cookie(CookieUtil.create(REFRESH_TOKEN, beforeRefresh)))
            .andExpect(status().isOk())
            .andDo(print())
            .andReturn();

    MockHttpServletResponse response = mvcResult.getResponse();
    Cookie cookie = response.getCookie(REFRESH_TOKEN);
    assertThat(cookie).as("쿠키에 RT Key가 없습니다.").isNotNull();
    assertThat(cookie.isHttpOnly()).as("쿠키에 HttpOnly가 True로 설정되지 않았습니다.").isTrue();
    String afterRefresh = cookie.getValue();
    assertThat(afterRefresh).as("쿠키에 새로운 RT 값이 없습니다.").isNotNull().isNotBlank();
    assertThat(refreshTokenCacheRepository.get(CACHE_USERNAME))
        .as("새로운 RT와 캐쉬의 RT가 서로 다릅니다.")
        .isEqualTo(afterRefresh);
    assertThat(afterRefresh).as("요청 쿠키 RT와 새로운 RT가 똑같습니다.").isNotEqualTo(beforeRefresh);
  }

  @Test
  @DisplayName("RT가 만료됨 -> Cache에서 RT 삭제")
  void cacheDelExpiredRefreshToken() throws Exception {
    long expiredTime = 1000L;
    String expiredRefreshToken =
        JwtUtil.createJwt(CATEGORY_REFRESH, CACHE_USERNAME, ROLE_ + MEMBER, expiredTime);
    refreshTokenCacheRepository.save(CACHE_USERNAME, expiredRefreshToken);

    Thread.sleep(1100L);

    MvcResult mvcResult =
        mockMvc
            .perform(post("/reissue").cookie(CookieUtil.create(REFRESH_TOKEN, expiredRefreshToken)))
            .andDo(print())
            .andExpect(status().isFound())
            .andReturn();
    assertThat(refreshTokenCacheRepository.equalsFrom(CACHE_USERNAME,expiredRefreshToken))
        .as("cache에 RT가 남아있습니다.")
        .isFalse();
  }
}
