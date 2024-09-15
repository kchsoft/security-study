package security_study.auth.controller;

import static org.springframework.http.HttpStatus.*;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import security_study.auth.dto.request.JoinRequestDto;
import security_study.auth.service.JoinService;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public ResponseEntity<String> joinProcess(@RequestBody JoinRequestDto joinRequestDto) {

        joinService.joinProcess(joinRequestDto);

    return ResponseEntity.status(OK).body("join ok");
    }
}
