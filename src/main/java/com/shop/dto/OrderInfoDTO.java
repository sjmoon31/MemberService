package com.shop.dto;

import com.shop.domain.enums.OrderStsType;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class OrderInfoDTO {
    private Long orderInfoSeq;
    private ProductStockDTO productStock;
    private ProductDTO productDTO;
    private int quantity;
    private String address;
    private PaymentDTO payment;
    private LocalDateTime orderDate;
    private MemberDTO member;
    private OrderStsType orderStsType;
}
