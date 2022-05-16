package hello.jwt.config;

import hello.jwt.config.jwt.JwtAuthenticationFilter;
import hello.jwt.config.jwt.JwtAuthorizationFilter;
import hello.jwt.filter.MyFilter1;
import hello.jwt.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CorsFilter corsFilter;
    private final UsersRepository usersRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*
        http.(new MyFilter1()); 에러가난다
        필터의 순서를 지정해줘야된다.
        SecurityFilterChain 에 대해서 알아야 그전에 필터를 걸든 그후에 걸든 할수 있다.
         */
//        http.addFilterBefore(new MyFilter1(), SecurityContextPersistenceFilter.class);
        http.csrf().disable();
        http
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션없는 서버로 만들겠다, 세션을 사용하지 않겠다.
                .and()
                .addFilter(corsFilter)  //@CrossOrigin(인증X), 시큐리티 필터에 등록(인증O)
                .formLogin().disable()
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), usersRepository))
                /*
                .formLogin().disable() 설정으로 인하여
                기본 security 필터가 동작을 안한다. 그래서 /login 으로 들어와도 아무 동작이 없다.
                그래서 UsernamePasswordAuthenticationFilter 을 상속받은 new JwtAuthenticationFilter() 을 다시 등록 해준다.
                 */
                /*
                .httpBasic().disable()
                http의 기본 인증방식을 끈다.
                bearer 방식을 사용하기 때문에 설정을 끈다.
                 */
                .httpBasic().disable()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
        ;
    }
}
