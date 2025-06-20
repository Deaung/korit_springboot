package com.korit.authstudy.config;

import com.korit.authstudy.filter.StudyFilter;
import com.korit.authstudy.security.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final StudyFilter studyFilter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        // 요청을 보내는 쪽의 도메인 (사이트 주소)
        corsConfiguration.addAllowedOriginPattern(CorsConfiguration.ALL);
        // 요청 보내는 쪽에서 request, response HEADER 정보에 대한 제약설정
        corsConfiguration.addAllowedHeader(CorsConfiguration.ALL);
        // 요청시 보내는 쪽의 메서드(GET POST PUT DELETE OPTION 등등)
        corsConfiguration.addAllowedMethod(CorsConfiguration.ALL);

        // 요청 URL ("/api/users")에 대한 CORS 설정 적용을 위해 객체 생성
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",corsConfiguration);

        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {
        security.cors(Customizer.withDefaults());   //위에서 만든 cors 설정(Bean) HttpSecurity 에 적용
        security.csrf(csrf -> csrf.disable());  //  ssr 방식 아니니 REST API 방식에서 비활성화
        security.formLogin(formLogin -> formLogin.disable());   //서버 사이드 렌더링 로그인방식 비활성화
        security.httpBasic(httpBasic -> httpBasic.disable());   // http프로토콜 기본 로그인방식 비활성화
        security.logout(logout -> logout.disable());    // ssr 로그아웃 방식 비활성화

//        security.addFilterBefore(studyFilter, UsernamePasswordAuthenticationFilter.class);
        security.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // 특정요청 URL 에 대한 권한 설정
        security.authorizeHttpRequests(auth -> {
            auth.requestMatchers("/api/users","/api/users/login", "/api/users/login/status","/api/users/principal").permitAll();
            auth.anyRequest().authenticated();
        });

        // httpSecurity 객체에 설정한 모든정보를 기반으로 build 해서 SecurityFilterChain 객체 생성 후 Bean 등록
        return security.build();
    }
}
