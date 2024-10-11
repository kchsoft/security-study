package security_study.auth.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import security_study.auth.entity.MemberEntity;

public interface MemberRepository extends JpaRepository<MemberEntity, Integer> {

    Boolean existsByUsername(String username);

    MemberEntity findByUsername(String username);
}
