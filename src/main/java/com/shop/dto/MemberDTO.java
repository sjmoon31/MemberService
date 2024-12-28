package com.shop.dto;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class MemberDTO {
    private long memberSeq;
    private String memberId;
    private FileDTO profile;
    private String name;
    private String nickName;
    private String email;
    private String zipCode;
    private String address;
    private String detailAddress;
    private String telNo;
    private Role role;
    private String newPassword;
    private String password;
    private String authority;
    private List<MemberCouponDTO> memberCouponList = new ArrayList<>();
}
