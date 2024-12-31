package com.shop.contorller;

import com.shop.service.EmailService;
import com.shop.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * 이메일 Controller
 */
@Controller
@Slf4j
@RequiredArgsConstructor
public class EmailController {
    private final EmailService emailService;
    private final MemberService memberService;

    /**
     * 이메일 인증번호 전송
     * @param request
     * @return
     */
    @PostMapping("/sendEmail")
    public ResponseEntity<Map<String, Boolean>> sendEmail(@RequestBody Map<String, String> request) {
        Map<String, Boolean> resultMap = new HashMap<>();
        String title = "[MoonShop] 이메일 인증을 위한 인증 코드 발송";
        emailService.sendEmail(request.get("email"), title);
        resultMap.put("emailVerificationSent", true);
        return ResponseEntity.ok(resultMap);
    }
    /**
     * 이메일 인증
     * @param request
     * @return
     * @throws NoSuchAlgorithmException
     */
    @PostMapping("/emailAuth")
    public ResponseEntity<Map<String, Boolean>> emailAuth(@RequestBody Map<String, String> request) throws NoSuchAlgorithmException {
        Map<String, Boolean> resultMap = new HashMap<>();
        String email = request.get("email");
        boolean isVerified = false;
        if (emailService.verifyEmailCode(email, request.get("code"))) {
            if(memberService.selectMemberByEmail(email) != null){
                memberService.saveMemberEmail(email,email);
            }
            isVerified = true;
        }
        resultMap.put("isVerified", isVerified);
        return ResponseEntity.ok(resultMap);
    }
}
