package security_study.auth.dto.request;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class JoinRequestDto {
  private Long id;
  private String username;
  private String password;
  private String nickname;
  private String role;
}
