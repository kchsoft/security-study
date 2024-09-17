package security_study.auth.constant;

public class JwtConstant {
  public static final String REFRESH_TOKEN = "refresh_token";
  public static final String CATEGORY_ACCESS = "access";
  public static final String CATEGORY_REFRESH = "refresh";
  public static final String BEARER_PREFIX = "Bearer ";
  public static final Long ACCESS_TOKEN_EXPIRATION_TIME = (long) 5 * 60 * 1000; // 5 minute
  public static final Long REFRESH_TOKEN_EXPIRATION_TIME = (long) 24 * 60 * 60 * 1000; // 1 hour
}
