package security_study.auth.service;

import static security_study.auth.constant.AuthoritiesRoleName.MEMBER;
import static security_study.auth.constant.AuthoritiesRoleName.ROLE_;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import security_study.auth.dto.request.JoinRequestDto;
import security_study.auth.entity.MemberEntity;
import security_study.auth.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class JoinService {

  private final MemberRepository memberRepository;
  private final PasswordEncoder passwordEncoder;

  public boolean joinProcess(JoinRequestDto joinRequestDto) {

    String username = joinRequestDto.getUsername();
    String password = joinRequestDto.getPassword();

    Boolean isExist = memberRepository.existsByUsername(username);

    if (isExist) {
      return false;
    }

    MemberEntity member =
        MemberEntity.builder()
            .username(username)
            .password(passwordEncoder.encode(password))
            .role(ROLE_ + MEMBER)
            .nickname(joinRequestDto.getNickname())
            .build();

    memberRepository.save(member);
    return true;
  }
}
