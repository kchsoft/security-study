package security_study.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static security_study.auth.config.MemberInfoConstant.RAW_PASSWORD_TEST;
import static security_study.auth.config.MemberInfoConstant.USERNAME_TEST;
import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;
import static security_study.auth.constant.AuthoritiesRoleName.ROLE_;
import static security_study.auth.constant.JwtConstant.ACCESS_TOKEN_EXPIRATION_TIME;
import static security_study.auth.constant.JwtConstant.BEARER_PREFIX;
import static security_study.auth.constant.JwtConstant.CATEGORY_ACCESS;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import security_study.auth.config.AuthenticationManagerTestConfiguration;
import security_study.auth.domain.CustomUserDetails;
import security_study.auth.dto.request.LoginRequestDto;
import security_study.auth.dto.response.LoginResponseDto;
import security_study.auth.listener.ContextCreationListener;

@SpringBootTest
@AutoConfigureMockMvc
@Slf4j
@TestExecutionListeners(
    listeners = ContextCreationListener.class,
    mergeMode = MergeMode.MERGE_WITH_DEFAULTS)
@Import(AuthenticationManagerTestConfiguration.class)
public class JwtAccessTokenTest {

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

  @Test
  @DisplayName("로그인 -> Access Token 생성")
  void loginCreateAccessToken() throws Exception {

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
    String contentAsString = response.getContentAsString();
    LoginResponseDto responseDto = objectMapper.readValue(contentAsString, LoginResponseDto.class);
    assertThat(responseDto).isNotNull();
    assertThat(responseDto.getAccessToken()).isNotNull();
    String accessToken = responseDto.getAccessToken();

    assertThat(JwtUtil.getUsername(accessToken)).isEqualTo(USERNAME_TEST);
    assertThat(JwtUtil.getRole(accessToken)).isEqualTo(ROLE_ + MEMBER);
  }

  @Test
  @DisplayName("AT -> private uri 접근 성공")
  void accessTokenToPrivateUri() throws Exception {
    String accessToken =
        JwtUtil.createJwt(
            CATEGORY_ACCESS, USERNAME_TEST, ROLE_ + MEMBER, ACCESS_TOKEN_EXPIRATION_TIME);
    mockMvc
        .perform(get("/member").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("만료된 AT -> private uri 접근 실패")
  void expiredAccessTokenToPrivateUri() throws Exception {
    String accessToken = JwtUtil.createJwt(CATEGORY_ACCESS, USERNAME_TEST, ROLE_ + MEMBER, -1000L);
    MvcResult mvcResult =
        mockMvc
            .perform(get("/member").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
            .andExpect(status().is4xxClientError())
            .andReturn();

    MockHttpServletResponse response = mvcResult.getResponse();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
  }
}
