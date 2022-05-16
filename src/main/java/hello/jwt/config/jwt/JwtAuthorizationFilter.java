package hello.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import hello.jwt.config.auth.PrincipalDetails;
import hello.jwt.domain.Users;
import hello.jwt.repository.UsersRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/*
    시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있다.
    권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
    만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UsersRepository usersRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UsersRepository usersRepository) {
        super(authenticationManager);
        System.out.println("JwtAuthorizationFilter.JwtAuthorizationFilter");
        this.usersRepository = usersRepository;
    }

    //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게된다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
//        super.doFilterInternal(request, response, chain); 두필터가 두개라서 세션이 안만들어졌었음!!!!!!!!!!!!
        System.out.println("JwtAuthorizationFilter.doFilterInternal");
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = " + jwtHeader);

        //header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }
        //JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC512("jc")).build().verify(jwtToken).getClaim("username").asString();

        System.out.println("============================username = " + username);

        //서명이 정상적으로 됨
        if (username != null) {
            Users usersEntity = usersRepository.findByUsername(username).get();

            System.out.println("========================usersEntity = " + usersEntity);

            PrincipalDetails principalDetails = new PrincipalDetails(usersEntity);

            //Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication
                    = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            //강제로 시큐리티 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
    }
}
