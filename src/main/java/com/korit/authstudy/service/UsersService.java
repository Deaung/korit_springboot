package com.korit.authstudy.service;

import com.korit.authstudy.domain.entity.User;
import com.korit.authstudy.dto.JwtDto;
import com.korit.authstudy.dto.LoginDto;
import com.korit.authstudy.dto.UserRegisterDto;
import com.korit.authstudy.repository.UsersRepository;
import com.korit.authstudy.security.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor//final
public class UsersService {


    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UsersRepository repository;
    private final JwtUtil jwtUtil;

    public User register(UserRegisterDto dto) {
        User insertedUser = repository.save(dto.toEntity(bCryptPasswordEncoder));
        return insertedUser;
    }

    public JwtDto login(LoginDto loginDto) {
        List<User> foundUsers = repository.findByUsername(loginDto.getUsername());
        if (foundUsers.isEmpty()){
            throw new UsernameNotFoundException("사용자 정보를 확인하세요");
        }
        User user = foundUsers.get(0);
        if (!bCryptPasswordEncoder.matches(loginDto.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("사용자 정보를 확인하세요");
        }
        System.out.println("로그인 성공(토큰생성)");
        String token = jwtUtil.generateAccessToken(user.getId().toString());
        return JwtDto.builder()
                .accessToken(token)
                .build();
    }


}
