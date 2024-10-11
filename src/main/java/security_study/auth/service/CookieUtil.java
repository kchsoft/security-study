package security_study.auth.service;

import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Component;

public class CookieUtil {
  public static Cookie create(String key, String value) {
    Cookie cookie = new Cookie(key,value);
    cookie.setMaxAge(24*60*60); // 24 hour
//    cookie.setSecure(true); // https
    cookie.setPath("/"); // cookie scope
    cookie.setHttpOnly(true);
    return cookie;
  }

  public static Cookie invalidate(String key, String value) {
    Cookie cookie = new Cookie(key,value);
    cookie.setMaxAge(0);
//    cookie.setSecure(true); // https
    cookie.setPath("/"); // cookie scope
    cookie.setHttpOnly(true);
    return cookie;
  }
}
