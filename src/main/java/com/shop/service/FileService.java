package com.shop.service;

import com.shop.common.ModelMapperUtil;
import com.shop.domain.File;
import com.shop.dto.FileDTO;
import com.shop.repository.FileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class FileService {
    private final FileRepository fileRepository;

    /**
     * 파일정보 조회
     * @param fileSeq
     * @return
     */
    public FileDTO getFileInfo(Long fileSeq){
        File file = fileRepository.getReferenceById(fileSeq);
        FileDTO result = ModelMapperUtil.map(file, FileDTO.class);
        return result;
    }
}
