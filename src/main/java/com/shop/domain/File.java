package com.shop.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

@Entity
@Getter
@Table(name = "file")
public class File {
    @Id
    @Column(name ="file_seq")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long fileSeq = null;
    @Column(name = "file_name")
    private String fileName;
    @Column(name = "file_pth")
    private String filePth;
    @Column(name = "file_ext")
    private String fileExt;
    @Column(name = "file_size")
    private long fileSize;
    @Column(name = "reg_date")
    private LocalDateTime regDate;
    @Column(name = "mod_date")
    private LocalDateTime modDate;

    public void CreateFile(long fileSize, LocalDateTime regDate, LocalDateTime modDate, String ...file){
        this.fileName = file[0];
        this.filePth = file[1];
        this.fileExt = file[2];
        this.fileSize = fileSize;
        this.regDate = regDate;
        this.modDate = modDate;
    }
}
