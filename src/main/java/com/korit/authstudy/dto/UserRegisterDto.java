package com.korit.authstudy.dto;

import com.korit.authstudy.domain.entity.User;
import lombok.Data;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Data
public class UserRegisterDto {

    private String username;
    private String password;
    private String fullName;
    private String email;

    public User toEntity(BCryptPasswordEncoder bCryptPasswordEncoder){
        return User.builder()
                .username(username)
                .password(bCryptPasswordEncoder.encode(password))
                .fullName(fullName)
                .email(email)
                .build();
    }
}
