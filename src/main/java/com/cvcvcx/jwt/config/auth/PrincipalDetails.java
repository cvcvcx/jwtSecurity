package com.cvcvcx.jwt.config.auth;

import com.cvcvcx.jwt.domain.User;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
//마치 UserDto 와 같은 역할을 하게 된다.
//하지만, 만약 user의 정보가 필요하게 된다면, 여기서 getUsername 을 통해 가져간 다음 그걸 repository에서 조회하고, 그 데이터를
//userDto라는 타입으로 새로 만들어서 넘기는 것이 안전하다.
@Data
@RequiredArgsConstructor
public class PrincipalDetails implements UserDetails {

    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities= new ArrayList<>();
        user.getRoleList().forEach(item->{
            authorities.add(()->item);
        });

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
