package com.shop.repository;

import com.shop.domain.Member;
import com.shop.repository.custom.MemberConfig;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long>, MemberConfig {
}
