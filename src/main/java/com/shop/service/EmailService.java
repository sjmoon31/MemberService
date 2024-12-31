package com.shop.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

@Service
@Slf4j
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender emailSender;
    private final RedisService redisService;

    /**
     * 이메일 전송
     * @param toEmail
     * @param title
     */
    public void sendEmail(String toEmail, String title) {
        String authCode = createCode();
        SimpleMailMessage emailForm = createEmailForm(toEmail, title, authCode);
        try {
            emailSender.send(emailForm);
        } catch (RuntimeException e) {
            log.debug("MailService.sendEmail exception occur toEmail: {}, " +
                    "title: {}, text: {}", toEmail, title, authCode);
            e.printStackTrace();
        }
    }
    /**
     * 코드생성
     * @return
     */
    private String createCode() {
        int length = 6;
        try {
            Random random = SecureRandom.getInstanceStrong();
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < length; i++) {
                builder.append(random.nextInt(10));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            log.debug("MemberService.createCode() exception occur");
        }
        return null;
    }
    /**
     * 이메일 정보 set
     * @param toEmail
     * @param title
     * @param authCode
     * @return
     */
    private SimpleMailMessage createEmailForm(String toEmail, String title,String authCode) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject(title);
        message.setText(authCode);
        redisService.setDataExpire(toEmail, authCode, 60 * 30L);
        return message;
    }
    /**
     * 이메일 인증
     * @param email
     * @param code
     * @return
     */
    public Boolean verifyEmailCode(String email, String code) {
        String codeFoundByEmail = redisService.getData(email);
        if (codeFoundByEmail == null) {
            return false;
        }
        return codeFoundByEmail.equals(code);
    }
}
