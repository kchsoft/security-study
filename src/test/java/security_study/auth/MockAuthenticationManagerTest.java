package security_study.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;
import static security_study.auth.constant.AuthoritiesRoleName.ROLE_;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import security_study.auth.domain.CustomUserDetails;
import security_study.auth.jwt.JWTUtil;

@SpringBootTest
@AutoConfigureMockMvc
public class MockAuthenticationManagerTest {

  /*
  @Mock
   spring context와 독립적, 단위 테스트에 사용
   특정 동작을 시뮬레이션 한다.
   가짜 객체 -> 다른 외부 시스템으로 부터 격리 한다. ex) 가짜 객체는 DB 조회 등 무거운 작업을 하지 않음. + 다른 컴포넌트의 의존성을 감소시킨다.
   @Mock 객체는 메서드가 정의되어 있지 않다고 생각하자.
   따라서 테스트 메서드 내에서 when(),thenResult(),thenAnswer() 를 통해 @Mock 객체의 내부 메서드 내용을 정의해야 한다.
*/
  @Mock
  private List<String> mockedList;


  @MockBean
  AuthenticationManager authenticationManager;


  @Autowired
  private MockMvc mockMvc;

  @Autowired // spring context의 bean을 가져옴, spring 전체 기능을 통합적으로 테스트 할 시 사용
  private JWTUtil jwtUtil;

  @Autowired
  ObjectMapper objectMapper;

  @Autowired
  PasswordEncoder passwordEncoder;


  private final String USERNAME_TEST = "USERNAME_TEST";
  private final String RAW_PASSWORD_TEST = "PASSWORD_TEST";
  private final String WRONG_RAW_PASSWORD_TEST = "WRONG_PASSWORD_TEST";
  private String ENCODED_PASSWORD_TEST;
  private UserDetails dbMemberDetails;

  @BeforeEach
  void setUp() {

    ENCODED_PASSWORD_TEST = passwordEncoder.encode(RAW_PASSWORD_TEST);
    dbMemberDetails =
        CustomUserDetails.builder()
            .username(USERNAME_TEST)
            .password(ENCODED_PASSWORD_TEST)
            .role(ROLE_+MEMBER)
            .build();
  }

  @Test
  @DisplayName("로그인시 JWT 생성 및 응답 완료(HttpHeader) - AuthenticationManager")
  void loginCreateJwt() throws Exception {

    // 인증 객체 생성
    // 필드에서 @Mock을 붙여서 사용할 때와 기능은 동일함. 다만 Scope에 대한 부분을 고려하자.
    Authentication authentication = mock(Authentication.class);

    // when() -> 모의 객체의 특정 메서드 호출시, 메서드 동작 방법을 정의(프로그래밍) 할 때 사용한다.
    // thenReturn() -> 메서드 호출 이후에 반환할 값을 설정한다. / 고정된 값을 반환한다. ( when() 후에 연결되어 사용 )
    // ex) getPrincipal() 메서드가 호출되면, 사전에 정의한 dbMemberDetails 객체를 반환하도록 메서드를 정의한다.
    when(authenticationManager.authenticate(any())).thenReturn(authentication);
    when(authentication.getPrincipal()).thenReturn(dbMemberDetails);

    List<GrantedAuthority> authorities =
        Collections.singletonList(new SimpleGrantedAuthority(ROLE_+MEMBER));

    // thenAnswer() -> 메서드 호출(when) 시점의 상태나 입력에 따라 다른 동작을 할 수 있다. + 제네릭 타입 관련 문제 해결
    // thenAnswer()를 사용해서 when()에서 호출하는 메서드의 내부 구현체를 정의한다고 생각하면 된다.
    // ex) getAuthorities()를 호출하면, 사전에 정의한 authorities를 반환하라!
    // 사용 이유 : 메서드 인자에 기반한 응답 생성, 호출 횟수에 따른 다른 응답 제공, 복잡한 로직 시뮬, 예외 발생 조건 테스트
    when(authentication.getAuthorities()).thenAnswer(invocation -> authorities);

    CustomUserDetails loginRequest =
        CustomUserDetails.builder()
            .username(USERNAME_TEST)
            .password(
                WRONG_RAW_PASSWORD_TEST) // AuthenticationManager 객체를 mock 했기 때문에, 테스트에서 RAW와 ENCODE에 대한 비교가 없다.
            .role(ROLE_+MEMBER)
            .build();

    MvcResult result =
        mockMvc
            .perform(
                post("/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        objectMapper.writeValueAsString(loginRequest))) // 객체를 json 형태(string)로 변환
            .andExpect(status().isOk())
            .andExpect(header().exists(AUTHORIZATION))
            .andDo(print())
            .andReturn();

    MockHttpServletResponse response = result.getResponse();
    String token = response.getHeader(AUTHORIZATION);
    assertNotNull(token);
    assertTrue(token.startsWith("Bearer "));

    String actualToken = token.substring(7);
    assertEquals(USERNAME_TEST, jwtUtil.getUsername(actualToken));
    assertEquals(ROLE_+MEMBER, jwtUtil.getRole(actualToken));
    assertFalse(jwtUtil.isExpired(actualToken));
  }
}
