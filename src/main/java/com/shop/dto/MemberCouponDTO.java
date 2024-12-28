package com.shop.dto;

import lombok.Data;

@Data
public class MemberCouponDTO {
    private Long memberCouponSeq;
    private MemberDTO memberDTO;
    private CouponDTO couponDTO;
    private String useYn;
}
