package security_study.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import security_study.auth.domain.CustomUserDetails;
import security_study.auth.entity.MemberEntity;
import security_study.auth.repository.MemberRepository;

/*
 *
 * 로그인 시도시에 해당 클래스가 실행된다.
 * */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

  private final MemberRepository memberRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    MemberEntity member = memberRepository.findByUsername(username);
    if (member != null) {
      return CustomUserDetails.builder()
          .username(member.getUsername())
          .password(member.getPassword())
          .role(member.getRole())
          .build();
    }

    return null;
  }
}
