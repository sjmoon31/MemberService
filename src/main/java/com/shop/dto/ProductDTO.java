package com.shop.dto;

import com.shop.domain.enums.ProductType;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
public class ProductDTO {
    private Long productSeq = 0L;
    private Long sellerSeq;
    private String productName;
    private String productContent;
    private String rpImageSeq;
    private int price;
    private LocalDateTime regDate;
    private LocalDateTime modDate;
    private ProductType productType;
    private long productTypeCount;
    private String productTypeCd;
    private List<ProductFileDTO> productFileList = new ArrayList<>();
    private List<ProductStockDTO> productStockList = new ArrayList<>();
    private List<HeartDTO> heartList = new ArrayList<>();
    private String filePth;
    private Map<String,String> sizeTypes = new HashMap<>();
    private String sizeType;
    private HeartDTO heart = null;
    private String updateYn;
    private String userEmail;
    private int page;
}
