package com.shop.dto;

import lombok.Data;

@Data
public class FileDTO {
    private Long fileSeq;
    private String fileName;
    private String filePth;
    private String fileExt;
}
