package com.shop.dto.oauth;

import lombok.Data;

/**
 * 토큰 DTO
 */
@Data
public class TokenDTO {
    private String accessToken;
    private String userName;
    private String userEmail;
    private long expireTime;

    public TokenDTO(String accessToken){
        this.accessToken = accessToken;
    }

    public TokenDTO(String accessToken, String userEmail, String userName){
        this.accessToken = accessToken;
        this.userEmail = userEmail;
        this.userName = userName;
    }
}
