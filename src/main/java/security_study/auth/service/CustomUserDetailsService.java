package security_study.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import security_study.auth.domain.CustomUserDetails;
import security_study.auth.entity.MemberEntity;
import security_study.auth.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        MemberEntity member = userRepository.findByUsername(username);

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
