package com.shop.repository.impl;

import com.querydsl.jpa.impl.JPAQueryFactory;
import com.shop.domain.File;
import com.shop.domain.Member;
import com.shop.domain.QMember;
import com.shop.repository.custom.MemberConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class MemberRepositoryImpl implements MemberConfig {
    private final JPAQueryFactory queryFactory;

    QMember qmember = QMember.member;
    public Member findByMemberId(String memberId) {
        return queryFactory.selectFrom(qmember)
                .where(qmember.memberId.eq(memberId))
                .fetchOne();
    }
    public long updateProfile(String email, File file) {
        return queryFactory.update(qmember)
                .set(qmember.profile,file)
                .where(qmember.email.eq(email))
                .execute();
    }
    public long updatePassword(String email, String newPassword) {
        return queryFactory.update(qmember)
                .set(qmember.password,newPassword)
                .where(qmember.email.eq(email))
                .execute();
    }
    public long updateEmail(String memberId, String email) {
        return queryFactory.update(qmember)
                .set(qmember.email,email)
                .where(qmember.memberId.eq(memberId))
                .execute();
    }

    public Optional<Member> findByEmail(String email){
        return Optional.ofNullable(queryFactory.selectFrom(qmember)
                .where(qmember.email.eq(email))
                .fetchOne());
    }
}
