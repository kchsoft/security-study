package security_study.auth;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static security_study.auth.constant.AuthoritiesRoleName.*;
import static security_study.auth.constant.JwtConstant.CATEGORY_REFRESH;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN;
import static security_study.auth.constant.JwtConstant.REFRESH_TOKEN_EXPIRATION_TIME;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import security_study.auth.domain.CustomUserDetails;
import security_study.auth.dto.request.LoginRequestDto;
import security_study.auth.dto.response.LoginResponseDto;
import security_study.auth.jwt.JwtUtil;
import security_study.auth.repository.RefreshTokenRepository;

@SpringBootTest
@AutoConfigureMockMvc
public class JwtTest {

  /*
  @Autowired
   spring context에 등록된 bean을 가져옴, spring 전체 기능을 통합적으로 테스트 할 시 사용
  */
  @Autowired private MockMvc mockMvc;
  @Autowired private JwtUtil jwtUtil;
  @Autowired private ObjectMapper objectMapper;
  @Autowired private PasswordEncoder passwordEncoder;

  /*
  @Mock
   spring context와 독립적, 단위 테스트에 사용
   특정 동작을 시뮬레이션 한다.
   가짜 객체 -> 다른 외부 시스템으로 부터 격리 한다. ex) 가짜 객체는 DB 조회 등 무거운 작업을 하지 않음. + 다른 컴포넌트의 의존성을 감소시킨다.
   @Mock 객체는 메서드가 정의되어 있지 않다고 생각하자.
   따라서 테스트 메서드 내에서 when(),thenResult(),thenAnswer() 를 통해 @Mock 객체의 내부 메서드 내용을 정의해야 한다.
  */
  @Mock private List<String> mockedList;

  /*
   * @MockBean
   * spring security 가 사용하는 UserDetailsService 대신, 여기있는 memberDetailsService 가 대신 실행된다.
   * 즉, 실제 돌아가는 security 상에서 아래의 가짜 객체(memberDetailsService)로 바꿔치기 하는 것 이다.
   * */
  @MockBean private UserDetailsService memberDetailsService;
  @MockBean private RefreshTokenRepository refreshTokenRepository;

  private final String USERNAME_TEST = "USERNAME_TEST";
  private final String WRONG_USERNAME_TEST = "WRONG_USERNAME_TEST";
  private final String RAW_PASSWORD_TEST = "PASSWORD_TEST";
  private final String WRONG_RAW_PASSWORD_TEST = "WRONG_PASSWORD_TEST";
  private String WRONG_ENCODE_PASSWORD_TEST;
  private String ENCODED_PASSWORD_TEST;
  private UserDetails dbMemberDetails;

  @BeforeEach
  void setUp() {

    ENCODED_PASSWORD_TEST = passwordEncoder.encode(RAW_PASSWORD_TEST);
    WRONG_ENCODE_PASSWORD_TEST = passwordEncoder.encode(WRONG_RAW_PASSWORD_TEST);

    dbMemberDetails =
        CustomUserDetails.builder()
            .username(USERNAME_TEST)
            .password(ENCODED_PASSWORD_TEST)
            .role(ROLE_ + MEMBER)
            .build();
    when(memberDetailsService.loadUserByUsername(anyString())).thenReturn(dbMemberDetails);

    when(refreshTokenRepository.existsByRefreshToken(anyString())).thenReturn(true);
  }

  @Test
  @DisplayName("mock 객체 활용 법에 대한 예시 가이드")
  public void mockObjectExplain() {
    // 모의 객체 행동 정의
    // 기본 사용법
    when(mockedList.get(anyInt())) // anyInt() -> 어떠한 정수와 "매칭" 될 수 있다는 것을 의미한다.
        .thenAnswer(
            invocation -> {
              int index =
                  invocation.getArgument(
                      0); // getArgument(0) -> mockedList.get() 메서드의 0번째 인자를 가져온다.
              return "Item " + index;
            });

    // 테스트
    assertEquals("Item 5", mockedList.get(5));
    assertEquals("Item 10", mockedList.get(10));
    assertEquals("Item 0", mockedList.get(0));
    assertEquals("Item -1", mockedList.get(-1));

    // 특정 값에 대한 다른 동작 정의
    when(mockedList.get(999)).thenReturn("Special Item");
    assertEquals("Special Item", mockedList.get(999));
    assertEquals("Item 1000", mockedList.get(1000));

    // 조건부 응답
    when(mockedList.set(anyInt(), anyString()))
        .thenAnswer(
            invocation -> { // invocation은 정의하고자 하는 [ 메서드 정보 (= mockedList.set()) ]를 가지고 있다고 생각하자.
              int index = invocation.getArgument(0); // set()의 anyInt() 에 해당
              String newValue = invocation.getArgument(1); // set()의 anyString()에 해당
              if (index < 0) {
                throw new IllegalArgumentException("Index must be non-negative");
              }
              return "Old value at " + index + " replaced with " + newValue;
            });

    assertEquals("Old value at 1 replaced with New", mockedList.set(1, "New"));
    assertThrows(IllegalArgumentException.class, () -> mockedList.set(-1, "Invalid"));

    // 호출 횟수에 따른 다른 응답
    final int[] callCount = {0};
    when(mockedList.size())
        .thenAnswer(
            invocation -> {
              callCount[0]++;
              return callCount[0] * 10;
            });

    assertEquals(10, mockedList.size());
    assertEquals(20, mockedList.size());
    assertEquals(30, mockedList.size());
  }

  @Test
  @DisplayName("로그인시 JWT 생성 및 응답 완료(HttpHeader) - UserDetailsServcie")
  void loginCreateJwt() throws Exception {
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
    assertNotNull(responseDto);
    assertNotNull(responseDto.getAccessToken());
    String accessToken = responseDto.getAccessToken();

    assertEquals(USERNAME_TEST, jwtUtil.getUsername(accessToken));
    assertEquals(ROLE_ + MEMBER, jwtUtil.getRole(accessToken));
    assertFalse(jwtUtil.isExpired(accessToken));

    Cookie cookie = response.getCookie(REFRESH_TOKEN);
    assertNotNull(cookie);
    assertEquals(REFRESH_TOKEN, cookie.getName());
    assertNotNull(cookie.getValue());
    assertTrue(cookie.isHttpOnly());
  }

  //
  //  @Test
  //  @DisplayName("잘못된 정보로 로그인 시도 - UserDetailsService")
  //  void wrongLoginDoNotCreateJwt() throws Exception {
  //    CustomUserDetails wrongLoginRequest =
  //        CustomUserDetails.builder()
  //            .username(WRONG_USERNAME_TEST)
  //            .password(WRONG_RAW_PASSWORD_TEST)
  //            .role(ROLE_+MEMBER)
  //            .build();
  //
  //    mockMvc
  //        .perform(
  //            post("/login")
  //                .contentType(MediaType.APPLICATION_JSON)
  //                .content(objectMapper.writeValueAsString(wrongLoginRequest)))
  //        .andExpect(status().isUnauthorized())
  //        .andDo(print())
  //        .andReturn();
  //  }
  //
  //  @Test
  //  @DisplayName("jwt의 role에 알맞는 request")
  //  void requestWithJwtRole() throws Exception {
  //    String token = jwtUtil.createJwt(USERNAME_TEST, ROLE_ + MEMBER, 3600000L);
  //
  //    mockMvc
  //        .perform(get("/member").header(AUTHORIZATION, BEARER_BLANK + token))
  //        .andExpect(status().isOk());
  //  }
  //
  //  @Test
  //  @DisplayName("jwt가 아닌 토큰 request")
  //  void requestInvalidJwt() throws Exception {
  //    String token = jwtUtil.createJwt(USERNAME_TEST, ROLE_ + MEMBER, 3600000L);
  //    mockMvc
  //        .perform(get("/member").header(AUTHORIZATION, BEARER_BLANK + "invalidtoken"))
  //        .andExpect(status().isForbidden());
  //  }
  //
  //  @Test
  //  @DisplayName("jwt의 role과 다른 request")
  //  void requestInvalidRoleWithJwt() throws Exception {
  //    String invalidRoleWithToken = jwtUtil.createJwt(USERNAME_TEST, ROLE_ + MEMBER, 1000L);
  //    mockMvc
  //        .perform(get("/admin").header(AUTHORIZATION, BEARER_BLANK + invalidRoleWithToken))
  //        .andExpect(status().isForbidden());
  //  }
  //
  //  @Test
  //  @DisplayName("기한 만료된 jwt request ")
  //  void requestExpiredToken() throws Exception {
  //    String expiredToken = jwtUtil.createJwt(USERNAME_TEST, ROLE_ + MEMBER, -1000L);
  //
  //    mockMvc
  //        .perform(get("/member").header(AUTHORIZATION, BEARER_BLANK + expiredToken))
  //        .andExpect(status().isForbidden());
  //  }
  //
  //  @Test
  //  @DisplayName("jwt가 없는 request")
  //  void requestNonJwt() throws Exception {
  //    mockMvc.perform(get("/member")).andExpect(status().isForbidden());
  //  }

  @Test
  @DisplayName("refresh 토큰 요청시 성공")
  void requestReissueJwt() throws Exception {
    String refreshToken =
        jwtUtil.createJwt(
            CATEGORY_REFRESH, USERNAME_TEST, ROLE_ + MEMBER, REFRESH_TOKEN_EXPIRATION_TIME);

    MvcResult result =
        mockMvc
            .perform(post("/reissue").cookie(new Cookie(REFRESH_TOKEN, refreshToken)))
            .andExpect(status().isOk())
            .andExpect(
                jsonPath("$.accessToken").exists()) // $ == json의 root, accessToken은 json의 key
            .andDo(print())
            .andReturn();

    MockHttpServletResponse response = result.getResponse();
    String contentAsString = response.getContentAsString();
    LoginResponseDto responseDto = objectMapper.readValue(contentAsString, LoginResponseDto.class);

    assertNotNull(responseDto);
    assertNotNull(responseDto.getAccessToken());
    String newAccessToken = responseDto.getAccessToken();

    assertEquals(USERNAME_TEST, jwtUtil.getUsername(newAccessToken));
    assertEquals(ROLE_ + MEMBER, jwtUtil.getRole(newAccessToken));
    assertFalse(jwtUtil.isExpired(newAccessToken));

    Cookie newRefreshTokenCookie = response.getCookie(REFRESH_TOKEN);
    assertNotNull(newRefreshTokenCookie);
    assertNotEquals(refreshToken, newRefreshTokenCookie.getValue());
  }
}
