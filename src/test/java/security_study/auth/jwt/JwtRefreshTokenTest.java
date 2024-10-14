package security_study.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static security_study.auth.config.MemberInfoConstant.RAW_PASSWORD_TEST;
import static security_study.auth.config.MemberInfoConstant.USERNAME_TEST;
import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;
import static security_study.auth.constant.AuthoritiesRoleName.ROLE_;
import static security_study.auth.constant.JwtConstant.CATEGORY_ACCESS;
import static security_study.auth.constant.JwtConstant.CATEGORY_REFRESH;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN_EXPIRATION_TIME;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import security_study.auth.config.AuthenticationManagerTestConfiguration;
import security_study.auth.dto.request.LoginRequestDto;
import security_study.auth.dto.response.ReissueResponseDto;
import security_study.auth.listener.ContextCreationListener;
import security_study.auth.repository.RefreshTokenCacheRepository;
import security_study.auth.service.CookieUtil;

@SpringBootTest
@AutoConfigureMockMvc
@TestExecutionListeners(
    listeners = ContextCreationListener.class,
    mergeMode = MergeMode.MERGE_WITH_DEFAULTS)
@Import(AuthenticationManagerTestConfiguration.class)
public class JwtRefreshTokenTest {

  /*
  @Autowired
   spring context에 등록된 bean을 가져옴, spring 전체 기능을 통합적으로 테스트 할 시 사용
  */
  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;

  /*
   * @MockBean
   * spring security 가 사용하는 AuthenticationManager 대신, 여기있는 mockAuthenticationManager 가 대신 실행된다.
   * 즉, 실제 돌아가는 security 상에서 아래의 가짜 객체(MockAuthenticationManager)로 바꿔치기 하는 것 이다.
   * */
  @Autowired private AuthenticationManager mockAuthenticationManager;
  @MockBean private RefreshTokenCacheRepository refreshTokenCacheRepository;

  @BeforeEach
  void setUp() {
    when(refreshTokenCacheRepository.equalsFrom(anyString(), anyString())).thenReturn(true);
  }

  @Test
  @DisplayName("로그인 -> Refresh Token 발급 성공")
  void loginCreateRefreshToken() throws Exception {
    LoginRequestDto loginRequest =
        LoginRequestDto.builder().username(USERNAME_TEST).password(RAW_PASSWORD_TEST).build();
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
    assertThat(cookie).as("").isNotNull();
    String refreshToken = cookie.getValue();
    assertThat(JwtUtil.getUsername(refreshToken))
        .as("입력한 유저 ID와 JWT 클레임의 유저 ID가 서로 다릅니다.")
        .isEqualTo(USERNAME_TEST);
    assertThat(JwtUtil.getRole(refreshToken))
        .as("사용자의 ROLE과 JWT 클레임의 ROLE이 서로 다릅니다.")
        .isEqualTo(ROLE_ + MEMBER);
    assertThat(JwtUtil.getCategory(refreshToken))
        .as("Refresh Token이 아닙니다.")
        .isEqualTo(CATEGORY_REFRESH);
    assertThat(cookie.isHttpOnly()).as("쿠키에 HttpOnly가 True로 설정되지 않았습니다.").isTrue();
  }

  @Test
  @DisplayName("RT로 reissue uri 접근 -> AT+RT 재발급")
  void reissueAccessTokenRefreshToken() throws Exception {
    String beforeRefresh =
        JwtUtil.createJwt(
            CATEGORY_REFRESH, USERNAME_TEST, ROLE_ + MEMBER, REFRESH_TOKEN_EXPIRATION_TIME);

    MvcResult mvcResult =
        mockMvc
            .perform(post("/reissue").cookie(CookieUtil.create(REFRESH_TOKEN, beforeRefresh)))
            .andExpect(status().isOk())
            .andDo(print())
            .andReturn();
    MockHttpServletResponse response = mvcResult.getResponse();

    // refresh token validation
    Cookie cookie = response.getCookie(REFRESH_TOKEN);
    assertThat(cookie).as("쿠키에 RT Key가 없습니다.").isNotNull();
    assertThat(cookie.isHttpOnly()).as("쿠키에 HttpOnly가 True로 설정되지 않았습니다.").isTrue();
    String afterRefresh = cookie.getValue();
    assertThat(afterRefresh).as("쿠키에 새로운 RT 값이 없습니다.").isNotNull();
    assertThat(afterRefresh).as("요청 쿠키 RT와 새로운 RT가 똑같습니다.").isNotEqualTo(beforeRefresh);

    // access token validation
    String contentAsString = response.getContentAsString();
    ReissueResponseDto reissueResponseDto =
        objectMapper.readValue(contentAsString, ReissueResponseDto.class);
    String newAccessToken = reissueResponseDto.getAccessToken();

    assertThat(newAccessToken)
        .as("accessToken이 없습니다.")
        .isNotNull()
        .as("accessToken이 비어있습니다.")
        .isNotBlank();
    assertThat(JwtUtil.getCategory(newAccessToken))
        .as("accessToken이 형식이 올바르지 않습니다.")
        .isEqualTo(CATEGORY_ACCESS);
    assertThat(JwtUtil.getRole(newAccessToken))
        .as("멤버 권한의 accessToken이 아닙니다.")
        .isEqualTo(ROLE_ + MEMBER);
    assertThat(JwtUtil.getUsername(newAccessToken))
        .as("올바른 사용자의 token이 아닙니다.")
        .isEqualTo(USERNAME_TEST);
  }

  @Test
  @DisplayName("만료된 RT -> 토큰 재발급X")
  void expiredRefreshToReissue() throws Exception {
    String expiredRefreshToken =
        JwtUtil.createJwt(CATEGORY_REFRESH, USERNAME_TEST, ROLE_ + MEMBER, -1000L);
    MvcResult mvcResult =
        mockMvc
            .perform(post("/reissue").cookie(CookieUtil.create(REFRESH_TOKEN, expiredRefreshToken)))
            .andDo(print())
            .andExpect(status().isFound())
            .andReturn();

    MockHttpServletResponse response = mvcResult.getResponse();
    assertThat(response).as("http 응답이 비어있습니다.").isNotNull();
    Cookie cookie = response.getCookie(REFRESH_TOKEN);
    assertThat(cookie).as("refresh Token 쿠키 key 값이 존재합니다.").isNull();
    String header = response.getHeader(AUTHORIZATION);
    assertThat(header).as("refresh Token 쿠기 value 값이 존재합니다.").isNull();
  }
}
