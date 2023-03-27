package com.cvcvcx.jwt.config;

import com.cvcvcx.jwt.config.auth.PrincipalDetailsService;
import com.cvcvcx.jwt.config.jwt.JwtAuthenticationFilter;
import com.cvcvcx.jwt.config.jwt.JwtAuthorizationFilter;
import com.cvcvcx.jwt.filter.MyFilter1;
import com.cvcvcx.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity//-> 시큐리티 활성화 => 기본 스프링 필터체인에 등록
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;
    private final PrincipalDetailsService principalDetailsService;

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
//                .addFilterBefore(new MyFilter1(), SecurityContextHolderFilter.class)
                .csrf()
                .disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin()
                .disable()
                .httpBasic()//
                .disable()
                .apply(new MyCustomDsl())
                .and()
                .authorizeRequests(authorize ->
                        authorize.antMatchers("/api/v1/user/**")
                                 .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                                 .antMatchers("/api/v1/manager/**")
                                 .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                                 .antMatchers("/api/v1/admin/**")
                                 .access("hasRole('ROLE_ADMIN')")
                                 .anyRequest()
                                 .permitAll())
                .build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl,HttpSecurity>{
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http.addFilter(corsFilter)
                    .addFilter(new JwtAuthorizationFilter(authenticationManager,userRepository))
                    .addFilter(new JwtAuthenticationFilter(authenticationManager));
        }
    }

}
