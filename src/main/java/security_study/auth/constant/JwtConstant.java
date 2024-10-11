package security_study.auth.constant;

public class JwtConstant {
  public static final String REFRESH_TOKEN = "refresh_token";
  public static final String CATEGORY_ACCESS = "access";
  public static final String CATEGORY_REFRESH = "refresh";
  public static final String BEARER_PREFIX = "Bearer ";
  public static final Long ACCESS_TOKEN_EXPIRATION_TIME = (long) 30 * 60 * 1000; // 30 minute
  public static final Long REFRESH_TOKEN_EXPIRATION_TIME = (long) 7 * 24 * 60 * 60 * 1000; // 7 day
}
