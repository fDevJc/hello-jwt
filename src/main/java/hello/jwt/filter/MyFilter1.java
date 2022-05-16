package hello.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("MyFilter1.doFilter");

        /*
        토큰: jc 이걸 만들어줘야함. id,pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답을 해준다.
        요청할때마다 header에 Authorization에 value값으로 토큰을 가지고 온다.
        그떄 토큰이 넘어어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면된다.
         */

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if (req.getMethod().equals("POST")) {
            System.out.println("POST 요청");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);

            if (headerAuth.equals("jc")) {
                chain.doFilter(req, res);
            } else {
                res.setCharacterEncoding("utf-8");
                res.getWriter().write("no 인증");
            }
        } else {
            chain.doFilter(req, res);
        }
    }
}
