package security_study.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static security_study.auth.config.MemberInfoConstant.NICKNAME_TEST;
import static security_study.auth.config.MemberInfoConstant.RAW_PASSWORD_TEST;
import static security_study.auth.config.MemberInfoConstant.USERNAME_TEST;
import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;
import static security_study.auth.constant.AuthoritiesRoleName.ROLE_;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import org.springframework.test.web.servlet.MockMvc;
import security_study.auth.dto.request.JoinRequestDto;
import security_study.auth.entity.MemberEntity;
import security_study.auth.listener.ContextCreationListener;
import security_study.auth.repository.MemberRepository;

@SpringBootTest
@AutoConfigureMockMvc
@TestExecutionListeners(
    listeners = ContextCreationListener.class,
    mergeMode = MergeMode.MERGE_WITH_DEFAULTS)
public class JoinTest {

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;
  @Autowired private MemberRepository memberRepository;

  private String JOIN_PREFIX = "JOIN_";
  private String JOIN_USERNAME = JOIN_PREFIX + USERNAME_TEST;
  private String JOIN_RAW_PASSWORD = JOIN_PREFIX + RAW_PASSWORD_TEST;
  private String JOIN_NICKNAME = JOIN_PREFIX + NICKNAME_TEST;

  @AfterEach
  void cleanUp() {}

  @Test
  @DisplayName("anony -> post /join")
  public void joinTest() throws Exception {
    String joinInfoJson =
        objectMapper.writeValueAsString(
            JoinRequestDto.builder()
                .username(JOIN_USERNAME)
                .password(JOIN_RAW_PASSWORD)
                .nickname(JOIN_NICKNAME)
                .role(ROLE_ + MEMBER)
                .build());
    mockMvc
        .perform(post("/join").contentType(MediaType.APPLICATION_JSON).content(joinInfoJson))
        .andExpect(status().isOk())
        .andDo(print());

    MemberEntity findMember = memberRepository.findByUsername(JOIN_USERNAME);
    assertThat(findMember).as("DB에 memberEntity 정보가 없습니다.").isNotNull();
    assertThat(JOIN_USERNAME).isEqualTo(findMember.getUsername());
    assertThat(JOIN_NICKNAME).isEqualTo(findMember.getNickname());
    assertThat(ROLE_ + MEMBER).isEqualTo(findMember.getRole());
  }
}
