package com.cvcvcx.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cvcvcx.jwt.config.auth.PrincipalDetails;
import com.cvcvcx.jwt.domain.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //실제로 로그인 요청을 하면 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter : 로그인 시도중");
        ObjectMapper om = new ObjectMapper();
        //입력이 들어올 때 request에 username과 password가 들어있는지 알아보는 것
        try {
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);
            System.out.println("=======================================================");
            //토큰을 만들어줘야함
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            //이거 할 때 PrincipalDetailsService의 loadUserByUsername()함수가 실행이 됩니다.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);
            PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principal.getUser()
                                        .getPassword());

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

//        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null){
//                System.out.println(input);
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }

        return null;
    }

    //인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principal = (PrincipalDetails) authResult.getPrincipal();
        log.info("로그인 성공했음! {}", principal);
        //실질적으로 클라이언트한테 jwt토큰을 만들어서 리턴하는 곳
        String jwtToken = JWT.create()
                             .withSubject("cos토큰")
                             .withExpiresAt(new Date(System.currentTimeMillis() + 60000 * 10))
                             .withClaim("id", principal.getUser()
                                                       .getId())
                             .withClaim("username", principal.getUser()
                                                             .getUsername())
                             .sign(Algorithm.HMAC256("cos"));
        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
