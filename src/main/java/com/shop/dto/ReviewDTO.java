package com.shop.dto;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;

@Data
public class ReviewDTO {
    private Long reviewSeq;
    private Long orderSeq;
    private String content;
    private int score;
    private double scoreAvg;
    private long reviewCount;
    private LocalDateTime regDate;
    private LocalDateTime modDate;
    private FileDTO file;
    private ProductStockDTO productStock;
    private MultipartFile imgFile;
    private OrderInfoDTO orderInfo;
    private String userEmail;
}
