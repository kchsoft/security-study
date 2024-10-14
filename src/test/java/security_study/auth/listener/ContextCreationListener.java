package security_study.auth.listener;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;

/*
* 테스트 실행 중, 특정 시점에 추가적인 동작을 수행항 수 있게 해준다.
* 적용할 테스트 클래스에 아래의 에노테이션을 적용한다.
* Listener -> Spring Test FrameWork의 일부이다. /  Spring Context 및 Test 실행과 관련된 Event에 반응함.
*
  @TestExecutionListeners(
    listeners = ContextCreationListener.class,
    mergeMode = MergeMode.MERGE_WITH_DEFAULTS) -> 기본 및 커스텀 리스너 모두 사용

*  MergeMode.REPLACE_DEFAULTS -> 커스텀 리스너만 사용
*
*
* 아래의 Listener 는 테스트 클래스의 정보 및 시간을 log에 남긴다.
* * */
public class ContextCreationListener implements TestExecutionListener {
  private static Set<ApplicationContext> contextSet = new HashSet<>();
  private static final Logger log = LoggerFactory.getLogger(ContextCreationListener.class);
  private LocalDateTime localStartTime;
  private static LocalDateTime globalStartTime = null;
  private RedisTemplate redisTemplate;

  @Override
  public void beforeTestClass(TestContext testContext) {
    if (globalStartTime == null) {
      globalStartTime = LocalDateTime.now();
      log.info("Global Test Start Time = {}", globalStartTime);
    }

    localStartTime = LocalDateTime.now();
    contextSet.add(testContext.getApplicationContext());
    log.info("{} Local Test Start Time = {}", testContext.getTestClass().getName(), localStartTime);
    log.info("Context Package Id = {}", testContext.getApplicationContext().getId());
    log.info("Spring Context Hashcode = {}", testContext.getApplicationContext().hashCode());
    log.info("Used Spring Context Size  = {}", contextSet.size());

    redisTemplate =
        testContext
            .getApplicationContext()
            .getBean("refreshTokenRedisTemplate", RedisTemplate.class);
  }

  /*
   * beforeTestMethod -> beforeTestExecution -> Test Class Method -> afterTestExecution -> afterTestMethod 순서로 진행.
   * afterTestExecution : 메소드 실행 직후, Transaction RollBack 이나 Context정리 이전에 호출됨.
   * afterTestMethod : 테스트 메서드 관련 모든 처리(RollBack,Context 정리 등등) 이후에 호출됨.
   * */
  @Override
  public void afterTestMethod(TestContext testContext) throws Exception {
    redisTemplate.delete(redisTemplate.keys("*"));
  }

  @Override
  public void afterTestClass(TestContext testContext) throws Exception {
    LocalDateTime endTime = LocalDateTime.now();
    log.info("{} Local Test Finish Time = {}", testContext.getTestClass().getName(), endTime);
    Duration localTestExecutionTime = Duration.between(localStartTime, endTime);
    log.info(
        "{} Local Test Execution Time = {}ms",
        testContext.getTestClass().getName(),
        localTestExecutionTime.toMillis());
    Duration globalTestExecutionTime = Duration.between(globalStartTime, endTime);
    log.info("Sum Of Test Execution Time = {}ms", globalTestExecutionTime.toMillis());
  }
}
