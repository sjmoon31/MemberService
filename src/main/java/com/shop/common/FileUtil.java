package com.shop.common;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.UUID;

@Slf4j
public class FileUtil {
    public static String saveFile(MultipartFile file, String rootPth, String filePth){
        String returnFlPth = "";
        try {
            File dir = new File(rootPth + filePth);
            // 디렉토리 생성
            if(!dir.exists()){
                dir.mkdir();
            }
            // 확장자
            String ext = file.getOriginalFilename().substring(file.getOriginalFilename().lastIndexOf("."));
            String fileName = UUID.randomUUID().toString() + ext;
            File destFile = new File(rootPth + filePth + "/" + fileName);
            file.transferTo(destFile);
            returnFlPth = filePth + "/" + fileName;

        }catch (Exception e){
            log.error("파일 동록 에러!!!");
        }
        return returnFlPth;
    }
}
