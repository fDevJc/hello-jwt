package hello.jwt;

import hello.jwt.domain.Users;
import hello.jwt.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@Component
@RequiredArgsConstructor
public class TestDataInit {
    private final UsersRepository usersRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostConstruct
    public void init() {
        Users users = new Users();
        users.setPassword(bCryptPasswordEncoder.encode("1"));
        users.setUsername("user");
        users.setRoles("ROLE_USER");
        usersRepository.save(users);

        Users manager = new Users();
        manager.setPassword(bCryptPasswordEncoder.encode("1"));
        manager.setUsername("manager");
        manager.setRoles("ROLE_MANAGER");
        usersRepository.save(manager);

        Users admin = new Users();
        admin.setPassword(bCryptPasswordEncoder.encode("1"));
        admin.setUsername("admin");
        admin.setRoles("ROLE_ADMIN");
        usersRepository.save(admin);
    }
}
