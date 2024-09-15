package security_study.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/member")
public class MemberController {
  @GetMapping
  public ResponseEntity<String> member() {
    return ResponseEntity.status(HttpStatus.OK).body("member ok");
  }
}
