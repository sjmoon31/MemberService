package com.shop.security;

import com.shop.dto.oauth.TokenDTO;
import com.shop.service.CustomUserDetailService;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    // 비밀키
    @Value("${spring.jwt.accessSecretKey}")
    private String accessSecretKey;
    // 토큰유효시간
    @Value("${spring.jwt.accessTokenExpireTime}")
    private long accessTokenExpireTime;

    private final CustomUserDetailService userDetailService;

    /**
     * JWT 토큰에서 사용자 ID 가져오기
     * @param authentication
     * @return
     */
    public TokenDTO generateToken(Authentication authentication) {
        Date now = new Date();
        //Access Token
        String accessToken = createToken(authentication.getName());
        TokenDTO token = new TokenDTO(accessToken);
        token.setExpireTime(now.getTime() + accessTokenExpireTime);
        return token;
    }

    /**
     * JWT 토큰 생성
     * @param memberId
     * @return
     */
    public String createToken(String memberId) {
        Date now =  new Date();
        Claims claims = Jwts.claims().setSubject(memberId);
        //Access Token
        return Jwts.builder()
                .setClaims(claims) // 정보 저장
                .setIssuedAt(now) // 토큰 발행 시간 정보
                .setExpiration(new Date(now.getTime() + accessTokenExpireTime)) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, accessSecretKey)  // 사용할 암호화 알고리즘과
                // signature 에 들어갈 secret값 세팅
                .compact();
    }

    /**
     * http 헤더로부터 bearer 토큰을 가져옴.
     * @param request
     * @return
     */
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * 토큰을 검증
     * @param token
     * @return
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(accessSecretKey).parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    /**
     * 토큰으로부터 User 객체를 생성하여 Authentication 객체를 반환
     * @param token
     * @return
     */
    public Authentication getAuthentication(String token) {
        String userEmail = getSubjectFromToken(token);
        UserDetails userDetails = userDetailService.loadUserByUsername(userEmail);
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * 토큰으로부터 클레임을 만들고 sub(memberEmail)를 반환
     * @param token
     * @return
     */
    public String getSubjectFromToken(String token) {
        token = token.startsWith("Bearer ") ? token.substring(7) : token;
        Jws<Claims> claims = Jwts.parser().setSigningKey(accessSecretKey).parseClaimsJws(token);
        return claims.getBody().getSubject();
    }

    // JWT 토큰에서 expire time 값을 가져오는 메소드
    public long getExpirationDateFromToken(String token) {
        try {
            final Claims claims = Jwts.parser().parseClaimsJws(token).getBody();
            return claims.getExpiration().getTime();
        }catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return 0;
    }
}