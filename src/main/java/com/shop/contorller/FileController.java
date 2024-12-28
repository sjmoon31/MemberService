package com.shop.contorller;

import com.shop.dto.FileDTO;
import com.shop.service.FileService;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * 파일 관련 Controller
 */
@Slf4j
@RestController
@CrossOrigin(origins = "http://localhost:3000")
@RequiredArgsConstructor
public class FileController {
    @Value("${root.filePath}")
    private String filePth;

    private final FileService fileService;

    /**
     * 파일 다운로드
     * @param response
     * @param fileSeq
     * @return
     */
    @GetMapping("/fileDownload")
    public String fileDownload(HttpServletResponse response, @RequestParam(value="fileSeq",required = false, defaultValue="0L") Long fileSeq) {
        try {
            FileDTO fileDTO = fileService.getFileInfo(fileSeq);
            response.setContentType( "image/gif" );
            ServletOutputStream bout = response.getOutputStream();

            String imgPath = filePth + fileDTO.getFilePth();
            String[] exts = {".bmp", ".jpg", ".gif", ".png", ".jpeg"};

            File f = new File(imgPath);
            if(f.exists()){
                imgPath = filePth + fileDTO.getFilePth();
            }
            FileInputStream fileInputStream = new FileInputStream(imgPath);
            int length;
            byte[] buffer = new byte[10];
            while ( ( length = fileInputStream.read( buffer ) ) != -1 )
                bout.write( buffer, 0, length );

        }catch (IOException ie) {
            log.info("fileDownload error : {}", ie.getMessage());
        }catch (Exception e){
            log.info("fileDownload error : {}", e.getMessage());
        }
        return null;
    }
}
