package security_study.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import security_study.auth.config.AuthenticationManagerTestConfiguration;
import security_study.auth.listener.ContextCreationListener;

@SpringBootTest
@AutoConfigureMockMvc
@TestExecutionListeners(
    listeners = ContextCreationListener.class,
    mergeMode = MergeMode.MERGE_WITH_DEFAULTS)
@Import(AuthenticationManagerTestConfiguration.class)
public class MockGuideTest {

  /*
  @Mock
   spring context와 독립적, 단위 테스트에 사용
   특정 동작을 시뮬레이션 한다.
   가짜 객체 -> 다른 외부 시스템으로 부터 격리 한다. ex) 가짜 객체는 DB 조회 등 무거운 작업을 하지 않음. + 다른 컴포넌트의 의존성을 감소시킨다.
   @Mock 객체는 메서드가 정의되어 있지 않다고 생각하자.
   따라서 테스트 메서드 내에서 when(),thenResult(),thenAnswer() 를 통해 @Mock 객체의 내부 메서드 내용을 정의해야 한다.
  */
  @Mock private List<String> mockedList;

  @Test
  @DisplayName("mock 객체 활용 법에 대한 예시 가이드")
  public void mockObjectExplain() {
    // 모의 객체 행동 정의
    // 필드에서 @Mock 혹은 메서드 내부에서 mock() 함수를 통해 모의 객체 생성 가능
    // ex) List<String> mockedList = mock(List.class
    // mock()를 사용하면 필드에서 @Mock을 붙여서 사용할 때와 기능은 동일함. 다만 Scope에 대한 부분을 고려하자.
    when(mockedList.get(anyInt())) // anyInt() -> 어떠한 정수와 "매칭" 될 수 있다는 것을 의미한다.
        .thenAnswer(
            invocation -> {
              int index =
                  invocation.getArgument(
                      0); // getArgument(0) -> mockedList.get() 메서드의 0번째 인자를 가져온다.
              return "Item " + index;
            });

    // 테스트
    /*
     * AssertJ VS JUnit - assert 라이브러리 차이
     * 1. AssertJ : 가독성 측면에서 좋음,메서드 체이닝 지원 / JUnit : 전통적인 정적메서드 호출
     * 2. AssertJ : 많은 assertion 메서드,매치 제공 -> 복잡한 객체 구조나 컬렉션 테스트 가능 / JUnit : AssertJ 만큼 다양하지 않음.
     * 3. AssertJ : 상세하고 명확안 에러 메시지 제공 / JUnit : 간단한 에러메시지
     * 4. AssertJ : 쉽게 만드는 사용자 정의 assertion 메서드 : JUnit : 비교적 복잡한 사용자 정의 assertion 메서드
     *
     * 따라서 AssertJ 사용한다.
     * */
    assertThat(mockedList.get(5)).isEqualTo("Item 5");
    assertThat(mockedList.get(10)).isEqualTo("Item 10");
    assertThat(mockedList.get(0)).isEqualTo("Item 0");
    assertThat(mockedList.get(-1)).isEqualTo("Item -1");

    // 특정 값에 대한 다른 동작 정의
    when(mockedList.get(999)).thenReturn("Special Item");
    assertThat(mockedList.get(999)).isEqualTo("Special Item");
    assertThat(mockedList.get(1000)).isEqualTo("Item 1000");

    // 조건부 응답
    when(mockedList.set(anyInt(), anyString()))
        .thenAnswer(
            invocation -> { // invocation은 정의하고자 하는 [ 메서드 정보 (= mockedList.set() ) ]를 가지고 있다고 생각하자.
              int index = invocation.getArgument(0); // set()의 anyInt() 에 해당
              String newValue = invocation.getArgument(1); // set()의 anyString()에 해당
              if (index < 0) {
                throw new IllegalArgumentException("Index must be non-negative");
              }
              return "Old value at " + index + " replaced with " + newValue;
            });

    assertThat(mockedList.set(1, "New")).isEqualTo("Old value at 1 replaced with New");
    assertThatThrownBy(() -> mockedList.set(-1, "Invalid"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Index must be non-negative");

    // 호출 횟수에 따른 다른 응답
    final int[] callCount = {0};
    when(mockedList.size())
        .thenAnswer(
            invocation -> {
              callCount[0]++;
              return callCount[0] * 10;
            });

    assertThat(mockedList.size()).isEqualTo(10);
    assertThat(mockedList.size()).isEqualTo(20);
    assertThat(mockedList.size()).isEqualTo(30);
  }
}
