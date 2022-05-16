package hello.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import hello.jwt.config.auth.PrincipalDetails;
import hello.jwt.domain.Users;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;


/*
스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
/login 이라고 요청해서 username, password를 post로 전송하면해당 필터가 동작
현재는 formLogin().disable() 설정이 켜져있기때문에 해당 필터가 동작을 안한다.
그래서 해당 필터를 다시 등록해줘야한다.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication");
        /*
        1.username, password를 받아서
        2.정상인지 로그 시도, authenticationManager로 로그인시도를 하면
        PrincipalDetailsService가 호출 loadUserByUsername() 이 실행
        3.PrincipalDetails를 세션에 담고(담는 이유는 권한 관리)
        4.JWT토큰을 만들어서 응답
         */
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            Users users = objectMapper.readValue(request.getInputStream(), Users.class);

            System.out.println("users = " + users);
            System.out.println("users.getUsername() = " + users.getUsername());
            System.out.println("users.getPassword() = " + users.getPassword());

            //토큰을 만들어야한다. 폼로그인이면 자동으로 해준다.
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(users.getUsername(), users.getPassword());

            //PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            //정상이면 authentication 내 로그인 정보가 담긴다
            //DB의 username과 password가 일치한다
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            // => 출력이 된다는건 로그인 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("principalDetails.getUsers() = " + principalDetails.getUsers());
            System.out.println("principalDetails.getUsername() = " + principalDetails.getUsername());

            /*
            authentication 객체가 session 영역에 저장을 해야하고 그 방법은 return을 해주면됨.
            리턴의 이뉴는 권한 관리를 security가 대신 해주기 떄문에 편하려고 하는거.
            굳이 JWT 토큰을 사용하면서 세션을 만들 이유가없다. 단지 권한처리를 편하게 하기 위하여 session에 넣어준다.
             */
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    /*
    attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response해주면 됨
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication 가 실행되는건 인증이 완료되었다는 거 ");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //RSA방식은 아니고 Hash암호방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())    //토큰이름
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))   //만료기간(10분)
                .withClaim("id", principalDetails.getUsers().getId())   //
                .withClaim("username", principalDetails.getUsers().getUsername())
                .sign(Algorithm.HMAC512("jc"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
        //super.successfulAuthentication(request, response, chain, authResult);
    }
}
