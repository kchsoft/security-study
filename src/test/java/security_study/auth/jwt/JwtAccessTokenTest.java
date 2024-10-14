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
import org.springframework.boot.test.mock.mockito.MockBean;
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
  @MockBean private AuthenticationManager mockAuthenticationManager;

  private String AT_PREFIX = "AT_";
  private String AT_USERNAME = AT_PREFIX + USERNAME_TEST;
  private String AT_PASSWORD = AT_PREFIX + RAW_PASSWORD_TEST;

  private UserDetails dbMemberDetails;

  @BeforeEach
  void setUp() {

    dbMemberDetails =
        CustomUserDetails.builder()
            .username(AT_USERNAME)
            .password(
                AT_PASSWORD) // AuthenticationManager 객체를 mock 할 것이기 때문에, 테스트에서 RAW와 ENCODE 패스워드에 대한
            // 비교가 없다.
            .role(ROLE_ + MEMBER)
            .build();

    Authentication mockAuthentication = mock(Authentication.class);

    // when() -> 모의 객체의 특정 메서드 호출시, 메서드 동작 방법을 정의(프로그래밍) 할 때 사용한다.
    // thenReturn() -> 메서드 호출 이후에 반환할 값을 설정한다. / 고정된 값을 반환한다. ( when() 후에 연결되어 사용 )
    // ex) getPrincipal() 메서드가 호출되면, 사전에 정의한 dbMemberDetails 객체를 반환하도록 메서드를 정의한다.
    when(mockAuthenticationManager.authenticate(any())).thenReturn(mockAuthentication);
    when(mockAuthentication.getPrincipal())
        .thenAnswer(
            param -> {
              log.info("execute mock method = {}", param.getMethod());
              return dbMemberDetails;
            });

    // thenAnswer() -> 메서드 호출(when) 시점의 상태나 입력에 따라 다른 동작을 할 수 있다. + 제네릭 타입 관련 문제 해결
    // thenAnswer()를 사용해서 when()에서 호출하는 메서드의 내부 구현체를 정의한다고 생각하면 된다.
    // ex) getAuthorities()를 호출하면, 사전에 정의한 dbMemberDetails의 authorities를 반환하라!
    // 사용 이유 : 메서드 인자에 기반한 응답 생성, 호출 횟수에 따른 다른 응답 제공, 복잡한 로직 시뮬, 예외 발생 조건 테스트
    when(mockAuthentication.getAuthorities()).thenAnswer(param -> dbMemberDetails.getAuthorities());
  }

  @Test
  @DisplayName("로그인 -> Access Token 생성")
  void loginCreateAccessToken() throws Exception {
    LoginRequestDto loginRequest =
        LoginRequestDto.builder().username(AT_USERNAME).password(AT_PASSWORD).build();
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

    assertThat(JwtUtil.getUsername(accessToken)).isEqualTo(AT_USERNAME);
    assertThat(JwtUtil.getRole(accessToken)).isEqualTo(ROLE_ + MEMBER);
  }

  @Test
  @DisplayName("AT -> private uri 접근 성공")
  void accessTokenToPrivateUri() throws Exception {
    String accessToken =
        JwtUtil.createJwt(
            CATEGORY_ACCESS, AT_USERNAME, ROLE_ + MEMBER, ACCESS_TOKEN_EXPIRATION_TIME);
    mockMvc
        .perform(get("/member").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("만료된 AT -> private uri 접근 실패")
  void expiredAccessTokenToPrivateUri() throws Exception {
    String accessToken = JwtUtil.createJwt(CATEGORY_ACCESS, AT_USERNAME, ROLE_ + MEMBER, -1000L);
    MvcResult mvcResult =
        mockMvc
            .perform(get("/member").header(AUTHORIZATION, BEARER_PREFIX + accessToken))
            .andExpect(status().is4xxClientError())
            .andReturn();

    MockHttpServletResponse response = mvcResult.getResponse();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
  }
}
