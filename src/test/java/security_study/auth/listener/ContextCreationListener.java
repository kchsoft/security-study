package security_study.auth.listener;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalField;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;
import security_study.auth.AuthApplication;

/*
* 테스트 실행 중, 특정 시점에 추가적인 동작을 수행항 수 있게 해준다.
* 적용할 테스트 클래스에 아래의 에노테이션을 적용한다.
*
  @TestExecutionListeners(
    listeners = ContextCreationListener.class,
    mergeMode = MergeMode.MERGE_WITH_DEFAULTS) -> 기본 및 커스텀 리스너 모두 사용

*  MergeMode.REPLACE_DEFAULTS -> 커스텀 리스너만 사용
*
* * */
public class ContextCreationListener implements TestExecutionListener {
  private static Set<ApplicationContext> contextSet = new HashSet<>();
  private static final Logger log = LoggerFactory.getLogger(ContextCreationListener.class);
  private LocalDateTime startTime;

  @Override
  public void beforeTestClass(TestContext testContext) {
    startTime = LocalDateTime.now();
    log.info("{} start time = {}", testContext.getTestClass().getName() ,startTime);
    contextSet.add(testContext.getApplicationContext());
    log.info("context package name = {}",testContext.getApplicationContext().getId());
    log.info("Spring context hashcode = {}",testContext.getApplicationContext().hashCode());
    log.info("Used Spring context size  = {}",contextSet.size());

  }

  @Override
  public void afterTestClass(TestContext testContext) throws Exception {
    LocalDateTime endTime = LocalDateTime.now();
    log.info("{} finish time = {}",testContext.getTestClass().getName() ,endTime);
    Duration testExecutionTime = Duration.between(startTime, endTime);
    log.info("{} execution time = {}ms", testContext.getTestClass().getName(),testExecutionTime.toMillis());
  }

}
