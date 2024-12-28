package com.shop.dto;

import lombok.Data;

@Data
public class ProductFileDTO {
    private Long productFileSeq;
    private ProductDTO productDTO;
    private String repYn;
    private FileDTO file;
}
