package security_study.auth.dto.request;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class LoginRequestDto {
  private String username;
  private String password;
}
