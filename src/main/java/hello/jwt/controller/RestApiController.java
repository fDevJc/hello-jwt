package hello.jwt.controller;

import hello.jwt.domain.Users;
import hello.jwt.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;

@RequiredArgsConstructor
@RestController
public class RestApiController {
    private final UsersRepository usersRepository;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1> hello token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody Users users) {
//        users.setPassword(bCryptPasswordEncoder.encode(users.getPassword()));
        users.setRoles("ROLE_USER");
        usersRepository.save(users);
        return "회원가입성공";
    }

    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }

    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
