package com.shop.service;

import com.shop.common.FileUtil;
import com.shop.common.ModelMapperUtil;
import com.shop.domain.File;
import com.shop.domain.Member;
import com.shop.dto.MemberDTO;
import com.shop.dto.Role;
import com.shop.dto.oauth.TokenDTO;
import com.shop.repository.FileRepository;
import com.shop.repository.MemberRepository;
import com.shop.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class MemberService {
    @Value("${root.filePath}")
    private String filePath;
    @Value("${image.profile.path}")
    private String imageUploadPath;
    private final MemberRepository memberRepository;
    private final FileRepository fileRepository;

    /**
     * id로 member 정보 조회
     * @param id
     * @return
     */
    public MemberDTO selectMemberById(String id) {
        Member member = memberRepository.findByMemberId(id);
        MemberDTO memberDTO = null;
        if(member != null){
            memberDTO = ModelMapperUtil.map(member, MemberDTO.class);
        }
        return memberDTO;
    }

    /**
     * email로 member 정보 조회
     * @param email
     * @return
     */
    public MemberDTO selectMemberByEmail(String email) {
        Member member = memberRepository.findByEmail(email).get();
        MemberDTO memberDTO = null;
        if(member != null){
            memberDTO = ModelMapperUtil.map(member, MemberDTO.class);
        }
        return memberDTO;
    }

    /**
     * 프로필 저장
     * @param email
     * @param profile
     */
    @Transactional
    public void saveMemberProfile(String email, MultipartFile profile){
        // 현재 날짜와 시간 취득
        LocalDateTime nowDate = LocalDateTime.now();
        String filePth = imageUploadPath;
        String saveFilePth = FileUtil.saveFile(profile, filePath, filePth);
        File fileInfo = new File();
        fileInfo.CreateFile(profile.getSize(), nowDate, null, profile.getOriginalFilename(), saveFilePth, "jpg");
        fileRepository.save(fileInfo);
        memberRepository.updateProfile(email, fileInfo);
    }

    /**
     * 비밀번호 변경
     * @param memberDTO
     * @return
     */
    @Transactional
    public long changeMyPassword(MemberDTO memberDTO) {
        long result = 0;
        Member member = new Member();
        result = memberRepository.updatePassword(memberDTO.getMemberId(), memberDTO.getNewPassword());
        return result;
    }

    /**
     * 이메일 정보 저장
     * @param memberId
     * @param email
     */
    @Transactional
    public void saveMemberEmail(String memberId, String email){
        memberRepository.updateEmail(memberId,email);
    }

    /**
     * 회원가입
     * @param memberDTO
     */
    @Transactional
    public void signUpMember(MemberDTO memberDTO){
        Member member = new Member();
        // 현재 날짜와 시간 취득
        LocalDateTime nowDate = LocalDateTime.now();
        member.createMember(nowDate, Role.USER, memberDTO.getMemberId(), memberDTO.getName(), memberDTO.getPassword()
                ,memberDTO.getName(),memberDTO.getEmail(), memberDTO.getZipCode()
                , memberDTO.getAddress(), memberDTO.getDetailAddress(), memberDTO.getTelNo());
        memberRepository.save(member);
    }
}
