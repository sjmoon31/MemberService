package com.shop.dto;

import com.querydsl.core.annotations.QueryProjection;
import lombok.Data;

@Data
public class HeartDTO {
    private Long heartSeq;
    private Long productSeq;
    private String productName;
    private int price;
    private MemberDTO memberDTO;
    private ProductDTO productDTO;
    private ProductStockDTO productStock;
    private Long productImgFlSeq;
    private Long heartCnt;
    public HeartDTO(){

    }

    @QueryProjection
    public HeartDTO(Long heartSeq, Long productSeq, String productName, int price, Long productImgFlSeq, Long heartCnt){
        this.heartSeq = heartSeq;
        this.productSeq = productSeq;
        this.productName = productName;
        this.price = price;
        this.productImgFlSeq = productImgFlSeq;
        this.heartCnt = heartCnt;
    }
}
