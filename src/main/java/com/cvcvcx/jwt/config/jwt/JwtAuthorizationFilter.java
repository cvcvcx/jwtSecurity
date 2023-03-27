package com.cvcvcx.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cvcvcx.jwt.config.auth.PrincipalDetails;
import com.cvcvcx.jwt.domain.User;
import com.cvcvcx.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//시큐리티가 filter를 가지고있는데, 그중에 BasicAuthenticationFilter라는 것이있음
//권한이나, 인증이 필요한 특정 주소를 요청했을때 이 필터를 무조건 타게 되어있음
//권한이나 인증이 필요가 없으면, 이필터를 안탐
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청이됨");
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : "+jwtHeader );
        if(jwtHeader==null||!jwtHeader.startsWith("Bearer")){
            chain.doFilter(request,response);
            return;
        }

        String token = request.getHeader("Authorization").replace("Bearer ","");
        String username = JWT.require(Algorithm.HMAC256("cos")).build().verify(token).getClaim("username").asString();
        if(username!=null){
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails,null,principalDetails.getAuthorities());
            //강제로 시큐리티세션에 인증된 유저 정보 등록
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request,response);
        }
    }
}
