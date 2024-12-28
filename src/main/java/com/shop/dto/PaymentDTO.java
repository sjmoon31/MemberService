package com.shop.dto;

import com.shop.domain.enums.PaymentType;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
public class PaymentDTO {
    private Long paymentSeq;
    private OrderInfoDTO orderInfo;
    private LocalDateTime paymentDate;
    private int totalPrice;
    private PaymentType paymentType;
    private String payType;
    private MemberDTO member;
    private String address;
    private List<String> cartSeqList = new ArrayList<String>();
    private List<String> memberCouponSeqList = new ArrayList<String>();
    private Long memberCouponSeq;
    private String impUid;
    private String userEmail;
}
