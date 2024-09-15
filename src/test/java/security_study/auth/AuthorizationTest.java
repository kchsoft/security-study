package security_study.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static security_study.auth.constant.AuthoritiesRoleName.ADMIN;
import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import security_study.auth.dto.request.JoinRequestDto;

@SpringBootTest
@AutoConfigureMockMvc
// 전체 app context를 load하고 MockMvc를 자동으로 구성한다.
public class AuthorizationTest {

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;

  /*
   * @WithMockUser(roles = "MEMBER") -> MEMBER 권한을 가지고 test 시작, 앞에 'ROLE_' 을 붙이면 안된다.
   * */

  @Test
  @DisplayName("anony -> get /")
  public void anonyToPublic() throws Exception {
    mockMvc
        .perform(get("/"))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("anony -> post /join")
  public void anonyToPublicByJoin() throws Exception{
    String joinJson =
        objectMapper.writeValueAsString(
            JoinRequestDto.builder()
                .username("usernameTest")
                .password("passwordTest")
                .nickname("nicknameTest")
                .role(MEMBER)
                .build());
    mockMvc
        .perform(post("/join").contentType(MediaType.APPLICATION_JSON).content(joinJson))
        .andExpect(status().isOk())
        .andDo(print());
  }


  @Test
  @DisplayName("anony -> get /admin")
  public void anonyToProtectedByAdmin() throws Exception {
    mockMvc.perform(get("/admin")).andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("anony -> get /authenticated")
  public void anonyToProtectedByAuthenticated() throws Exception {
    mockMvc.perform(get("/authenticated")).andExpect(status().isForbidden());
  }


  @Test
  @WithMockUser(roles = MEMBER)
  @DisplayName("MEMBER -> get /member")
  public void memberToProtectedByMember() throws Exception {
    mockMvc.perform(get("/member")).andExpect(status().isOk());
  }

  @Test
  @WithMockUser(roles = MEMBER)
  @DisplayName("MEMBER -> get /admin")
  public void memberToProtectedByAdmin() throws Exception {
    mockMvc.perform(get("/admin")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(roles = ADMIN) // 역할의 사용자 시뮬레이션
  @DisplayName("ADMIN -> get /admin")
  public void adminToProtectedByAdmin() throws Exception {
    mockMvc.perform(get("/admin")).andExpect(status().isOk());
  }
}
