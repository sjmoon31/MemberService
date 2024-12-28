package com.shop.contorller;

import com.shop.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 토큰을 이용하여 이메일 조회
     * @param token
     * @return
     */
    @GetMapping("/auth")
    public String getTokenByEmail(@RequestHeader("Authorization") String token){
        String email = null;
        if (token != null && token.startsWith("Bearer ")) {
            token =  token.substring(7);
            if (jwtTokenProvider.validateToken(token)){ // access 토큰 인증
                email = jwtTokenProvider.getSubjectFromToken(token);
            }
        }
        return email;
    }
}
