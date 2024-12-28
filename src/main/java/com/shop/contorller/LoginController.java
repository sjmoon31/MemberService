package com.shop.contorller;

import com.shop.dto.MemberDTO;
import com.shop.dto.oauth.TokenDTO;
import com.shop.security.JwtTokenProvider;
import com.shop.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * 로그인 관련 Controller
 */
@RestController
@CrossOrigin(origins = "http://localhost:3000")
@RequiredArgsConstructor
public class LoginController {
    private final MemberService memberService;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager; // AuthenticationManager 주입

    /**
     * ID 중복체크
     * @param memberDTO
     */
    @PostMapping("/idDupChk")
    public ResponseEntity<Map<String, String>> idDupChk(MemberDTO memberDTO) {
        Map<String, String> resultMap = new HashMap<>();
        MemberDTO member = memberService.selectMemberById(memberDTO.getMemberId());
        String dupYn = "N";
        if (member != null) {
            dupYn = "Y";
        }
        resultMap.put("dupYn", dupYn);

        // ResponseEntity로 JSON 응답을 보내기
        return ResponseEntity.ok(resultMap);
    }
    /**
     * 회원가입
     * @param memberDTO
     * @return
     */
    @PostMapping("/signUp")
    public ResponseEntity<Void> signUp(MemberDTO memberDTO) {
        //WebSecurityConfigmemberDTO.setPassword(passwordEncoder.encode(memberDTO.getPassword()));
        memberService.signUpMember(memberDTO);
        return ResponseEntity.ok().build();
    }

    /**
     * 구글 로그인
     * @param request
     * @return
     */
    @PostMapping("/authenticate")
    public ResponseEntity<Map<String, Object>> authenticateUser(@RequestBody Map<String, String> request) {
        try {
            String token = request.get("accessToken");
            /// RestTemplate을 사용하여 Google API 호출
            RestTemplate restTemplate = new RestTemplate();
            String url = "https://www.googleapis.com/oauth2/v2/userinfo?alt=json&access_token=" + token;

            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );

            Map<String, Object> userInfo = response.getBody();
            String userEmail = (String) userInfo.get("email");
            String userName = (String) userInfo.get("name");
            String jwtToken = jwtTokenProvider.createToken(userEmail);
            TokenDTO tokenDTO = new TokenDTO(jwtToken, userEmail, userName);

            Map<String, Object> result = new HashMap<>();
            result.put("jwtToken", tokenDTO);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return  ResponseEntity.badRequest().build();
        }
    }

    /**
     * 로그인 처리
     * @return
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> loginData) {
        String email = loginData.get("email");
        String password = loginData.get("password");

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );

        MemberDTO memberDTO = memberService.selectMemberByEmail(email);

        String jwtToken = jwtTokenProvider.createToken(authentication.getName());
        TokenDTO tokenDTO = new TokenDTO(jwtToken, email, memberDTO.getName());

        Map<String, Object> result = new HashMap<>();
        result.put("jwtToken", tokenDTO);
        return ResponseEntity.ok(result);
    }
}
