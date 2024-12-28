package com.shop.contorller;

import com.shop.dto.MemberDTO;
import com.shop.security.JwtTokenProvider;
import com.shop.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * 사용자 관련 Controller
 */
@RestController
@CrossOrigin(origins = "http://localhost:3000")
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 마이페이지 조회
     * @param token
     * @return
     */
    @GetMapping("/myPage")
    public Map<String, Object> myPage(@RequestHeader("Authorization") String token){
        // 이메일 추출
        String email = jwtTokenProvider.getSubjectFromToken(token);
        MemberDTO member = memberService.selectMemberByEmail(email);
        Map<String, Object> response = new HashMap<>();
        response.put("member", member);
        return response;
    }
}