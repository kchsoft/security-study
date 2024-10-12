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
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import security_study.auth.domain.CustomUserDetails;
import security_study.auth.dto.request.LoginRequestDto;
import security_study.auth.listener.ContextCreationListener;
import security_study.auth.repository.BlacklistCacheRepository;
import security_study.auth.repository.RefreshTokenCacheRepository;
import security_study.auth.service.CookieUtil;

@SpringBootTest
@AutoConfigureMockMvc
@Slf4j
@TestExecutionListeners(
    listeners = ContextCreationListener.class,
    mergeMode = MergeMode.MERGE_WITH_DEFAULTS)
public class JwtRefreshTokenBlacklistTest {

  @Autowired MockMvc mockMvc;
  @Autowired BlacklistCacheRepository blacklistCacheRepository;
  @Autowired RefreshTokenCacheRepository refreshTokenCacheRepository;

  @Autowired
  @Qualifier("blacklistRedisTemplate")
  RedisTemplate<String, String> blacklistRedisTemplate;

  @Autowired ObjectMapper objectMapper;

  @MockBean AuthenticationManager mockAuthenticationManager;

  @Mock UserDetails dbMemberDetails;

  @BeforeEach
  void setup() {
    dbMemberDetails =
        CustomUserDetails.builder()
            .username(USERNAME_TEST)
            .password(RAW_PASSWORD_TEST)
            .role(ROLE_ + MEMBER)
            .build();

    Authentication authentication = mock(Authentication.class);
    when(authentication.getPrincipal()).thenReturn(dbMemberDetails);
    when(authentication.getAuthorities()).thenAnswer(answer -> dbMemberDetails.getAuthorities());

    when(mockAuthenticationManager.authenticate(any())).thenReturn(authentication);
  }

  @AfterEach
  void cleanup() {
    blacklistRedisTemplate.delete(blacklistRedisTemplate.keys("*"));
    refreshTokenCacheRepository.delete(USERNAME_TEST);
  }

  @Test
  @DisplayName("로그인 -> 발급된 RT는 Blacklist에 없다.")
  void newRefreshTokenNotExistInBlackList() throws Exception {
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
    assertThat(cookie).isNotNull();
    String refreshToken = cookie.getValue();
    assertThat(refreshToken).isNotNull().isNotBlank();
    assertThat(blacklistCacheRepository.isExist(refreshToken)).isFalse();
  }

  @Test
  @DisplayName("RT -> reissue uri 접근 -> 기존 RT BL에 있고, 새로운 RT BL에 없음.")
  void oldRefreshTokenExistInBlacklist() throws Exception {
    String beforeRefresh =
        JwtUtil.createJwt(
            CATEGORY_REFRESH, USERNAME_TEST, ROLE_ + MEMBER, REFRESH_TOKEN_EXPIRATION_TIME);
    refreshTokenCacheRepository.save(USERNAME_TEST, beforeRefresh);

    MvcResult mvcResult =
        mockMvc
            .perform(post("/reissue").cookie(CookieUtil.create(REFRESH_TOKEN, beforeRefresh)))
            .andExpect(status().isOk())
            .andDo(print())
            .andReturn();
    MockHttpServletResponse response = mvcResult.getResponse();

    // old refresh token validation
    assertThat(blacklistCacheRepository.isExist(beforeRefresh))
        .as("old RT가 Blacklist에 없습니다.")
        .isTrue();

    // new refresh token validation
    Cookie cookie = response.getCookie(REFRESH_TOKEN);
    assertThat(cookie).as("쿠키에 RT Key가 없습니다.").isNotNull();
    assertThat(cookie.isHttpOnly()).as("쿠키에 HttpOnly가 True로 설정되지 않았습니다.").isTrue();
    String afterRefresh = cookie.getValue();
    assertThat(afterRefresh).as("RT 값이 null 입니다.").isNotNull().as("RT 값이 \"\" 입니다.").isNotBlank();
    assertThat(blacklistCacheRepository.isExist(afterRefresh))
        .as("new RT가 Blacklist에 있습니다.")
        .isFalse();
  }

  @Test // refresh cache에 토큰이 있다고 가정함.
  @DisplayName("BL에 있는 RT -> reissue uri 접근 -> cache,blacklist 변화 없음")
  void BlacklistRefreshTokenDoNotMakeNewJwt() throws Exception {
    String blacklistRefresh =
        JwtUtil.createJwt(
            CATEGORY_REFRESH, USERNAME_TEST, ROLE_ + MEMBER, REFRESH_TOKEN_EXPIRATION_TIME);
    String cacheRefresh =
        JwtUtil.createJwt(
            CATEGORY_REFRESH, USERNAME_TEST, ROLE_ + MEMBER, REFRESH_TOKEN_EXPIRATION_TIME);

    blacklistCacheRepository.save(blacklistRefresh, USERNAME_TEST);
    refreshTokenCacheRepository.save(USERNAME_TEST, cacheRefresh);

    MvcResult mvcResult =
        mockMvc
            .perform(post("/reissue").cookie(CookieUtil.create(REFRESH_TOKEN, blacklistRefresh)))
            .andExpect(status().isBadRequest())
            .andDo(print())
            .andReturn();

    // blacklist refresh token validation
    assertThat(blacklistCacheRepository.isExist(blacklistRefresh))
        .as("BL RT가 Blacklist에 없습니다.")
        .isTrue();

    // cache refresh token validation
    assertThat(refreshTokenCacheRepository.isExist(USERNAME_TEST))
        .as("cache RT가 Cache에 없습니다.")
        .isTrue();
  }
}
