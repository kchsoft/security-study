package security_study.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import security_study.auth.config.AuthenticationManagerTestConfiguration;
import security_study.auth.listener.ContextCreationListener;

@SpringBootTest
@TestExecutionListeners(
		listeners = ContextCreationListener.class,
		mergeMode = MergeMode.MERGE_WITH_DEFAULTS)
@Import(AuthenticationManagerTestConfiguration.class)
class AuthApplicationTests {

	@Test
	void contextLoads() {
	}

}
