package com.cvcvcx.jwt.config.auth;

import com.cvcvcx.jwt.domain.User;
import com.cvcvcx.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//http://localhost:8080/login 요청이 올 때 실행이 됨 하지만 설정에서 formLogin disable을 해버려서 요청이 안됨
@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("PrincipalDetailsService 동작중... loadUserByUsername");
        User userEntity = userRepository.findByUsername(username);
        log.info("userEntity {}", userEntity);
        return new PrincipalDetails(userEntity);
    }
}
