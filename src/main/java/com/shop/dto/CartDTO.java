package com.shop.dto;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class CartDTO {
    public List<CartDTO> cartList= new ArrayList();
    private Long cartSeq;
    private MemberDTO member;
    private ProductDTO productDTO;
    private ProductStockDTO productStock;
    private int quantity;
    private int totalPrice;
    private Long memberSeq;
    private Long productStockSeq;
    private String productName;
    private String productSize;
    private int price;
    private List<String> cartSeqList =  new ArrayList();
    private String userEmail;
}
