package hello.jwt.config.auth;

import hello.jwt.domain.Users;
import hello.jwt.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/*
http://localhost:8080/login
기본으로는 동작해야하지만
SecurityConfig에서
formLoin().disabled() 설정을 해놓았기때문에 기본 url설정이 없어져서 해당 서비스를 안탄다
 */
@RequiredArgsConstructor
@Service
public class PrincipalDetailService implements UserDetailsService {

    private final UsersRepository usersRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailService.loadUserByUsername");

        Users userEntity = usersRepository.findByUsername(username).get();

        return new PrincipalDetails(userEntity);
    }
}
