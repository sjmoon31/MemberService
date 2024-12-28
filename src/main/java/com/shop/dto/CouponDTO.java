package com.shop.dto;

import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;
@Data
public class CouponDTO {
    private Long couponSeq;
    private String couponName;
    private int discRate;
    private int minPrice;
    private int maxDiscPrice;
    private LocalDate useStDate;
    private LocalDate useEdDate;
    private LocalDateTime regDate;
    private LocalDateTime modDate;
}
