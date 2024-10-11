package security_study.auth.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class MemberInfoConstant
{

  private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

  public static final String USERNAME_TEST = "USERNAME_TEST";
  public static final String NICKNAME_TEST = "NICKNAME_TEST";
  public static final String RAW_PASSWORD_TEST = "PASSWORD_TEST";
  public static String WRONG_USERNAME_TEST = "WRONG_USERNAME_TEST";
  public static final String WRONG_RAW_PASSWORD_TEST = "WRONG_PASSWORD_TEST";
  public static String WRONG_ENCODE_PASSWORD_TEST = passwordEncoder.encode(WRONG_RAW_PASSWORD_TEST);
  public static String ENCODED_PASSWORD_TEST = passwordEncoder.encode(RAW_PASSWORD_TEST);
}
