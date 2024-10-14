package security_study.auth.config;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static security_study.auth.config.MemberInfoConstant.RAW_PASSWORD_TEST;
import static security_study.auth.config.MemberInfoConstant.USERNAME_TEST;
import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;
import static security_study.auth.constant.AuthoritiesRoleName.ROLE_;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import security_study.auth.domain.CustomUserDetails;

@TestConfiguration
@Slf4j
public class AuthenticationManagerTestConfiguration {

  @Bean
  @Primary
  public AuthenticationManager testAuthenticationManager() {
    AuthenticationManager mockAuthenticationManager = mock(AuthenticationManager.class);
    UserDetails dbMemberDetails =
        CustomUserDetails.builder()
            .username(USERNAME_TEST)
            .password(
                RAW_PASSWORD_TEST) // AuthenticationManager 객체를 mock 할 것이기 때문에, 테스트에서 RAW와 ENCODE 패스워드에 대한
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
    return mockAuthenticationManager;
  }

  @Bean
  @Primary
  public AuthenticationConfiguration testAuthenticationConfiguration() throws Exception {
    AuthenticationConfiguration mockAuthConfig = mock(AuthenticationConfiguration.class);
    AuthenticationManager authenticationManager = testAuthenticationManager();
    when(mockAuthConfig.getAuthenticationManager()).thenReturn(authenticationManager);
    return mockAuthConfig;
  }
}
