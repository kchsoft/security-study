package security_study.auth.service;

import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;
import static security_study.auth.constant.AuthoritiesRoleName.ROLE_;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import security_study.auth.dto.request.JoinRequestDto;
import security_study.auth.entity.MemberEntity;
import security_study.auth.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class JoinService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public void joinProcess(JoinRequestDto joinRequestDto) {

    String username = joinRequestDto.getUsername();
    String password = joinRequestDto.getPassword();

    Boolean isExist = userRepository.existsByUsername(username);

    if (isExist) {
      return;
    }

    MemberEntity member =
        MemberEntity.builder()
            .username(username)
            .password(passwordEncoder.encode(password))
            .role(ROLE_ + MEMBER)
            .nickname(joinRequestDto.getNickname())
            .build();

    userRepository.save(member);
  }
}
