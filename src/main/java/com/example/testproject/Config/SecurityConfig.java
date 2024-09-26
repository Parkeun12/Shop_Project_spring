package com.example.testproject.Config;

import com.example.testproject.Service.UserSecurityService;
import com.example.testproject.Service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity // 해당 파일로 시큐리티 활성화
@Configuration // IoC 등록
@RequiredArgsConstructor
public class SecurityConfig {
    @Autowired
    private UserService userService;
    @Autowired
    private UserSecurityService userSecurityService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
                httpSecurity.csrf().disable().cors().disable()//REST API에서 csrf 보안이 필요없기 때문에 비활성화,
                .authorizeHttpRequests(request -> request
//                        .requestMatchers("/admin/**","/product/**").hasRole("ROLE_ADMIN") //admin 접근. hasRole 사용자가 주어진 역할이 있다면 접근을 허용
//                        .requestMatchers("/users/login","/users/new").hasRole("ROLE_USER")
                        //css나 img 적용 안될 때 확인하기
                        //antMatchers 파라미터로 설정한 리소스 접근을 인증절차 없이 허용
                        .requestMatchers("/users/**","/js/**", "/css/**", "/img/**","/product/**","/mainshop/**","/wishlist/**").permitAll()
                        .anyRequest().authenticated()

                )
                .formLogin(login -> login
                        .loginPage("/users/login").permitAll() //로그인페이지 URL
                        .defaultSuccessUrl("/mainshop_user", true) //로그인 성공시 이동할 페이지
                        .usernameParameter("username") // 로그인시 사용할 파라미터 이름 설정
                        .failureUrl("/users/login/error") // 로그인 실패시 이동할 URL
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/users/logout"))//로그아웃 URL
                        .logoutSuccessUrl("/mainshop") //로그아웃 성공시 URL
                        .invalidateHttpSession(true) // 로그아웃 이후 세션 전체 삭제 여부
                );
        return httpSecurity.build();
    }

    //AuthenticationManager는 스프링 시큐리티의 인증을 담당
    //
    //AuthenticationManager 빈 생성시 스프링의 내부 동작으로 인해
    //
    //위에서 작성한 UserSecurityService와 PasswordEncoder가 자동으로 설정
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}

