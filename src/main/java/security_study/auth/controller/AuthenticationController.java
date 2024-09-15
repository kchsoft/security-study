package security_study.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {

  @GetMapping("/authenticated")
  public String authenticate(){
    return "authenticated ok";
}
}
