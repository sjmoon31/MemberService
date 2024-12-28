package com.shop.domain;

import com.shop.domain.common.BaseTimeEntity;
import com.shop.dto.Role;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Entity
@Getter
@Table(name = "member")
public class Member extends BaseTimeEntity {
    @Id
    @Column(name ="member_seq")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberSeq;
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "profile_seq", foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT))
    private File profile;
    @Column(name = "member_id")
    private String memberId;
    @Column(name = "name")
    private String name;
    @Column(name = "password")
    private String password;
    @Column(name = "nick_name")
    private String nickName;
    @Column(name = "email")
    private String email;
    @Column(name = "zip_code")
    private String zipCode;
    @Column(name = "address")
    private String address;
    @Column(name = "detail_address")
    private String detailAddress;
    @Column(name = "tel_no")
    private String telNo;
    @Column(name = "join_date")
    private LocalDateTime joinDate;
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Role role;
    @Column
    private String picture;
    /*@JsonManagedReference
    @OneToMany(mappedBy = "member", cascade = CascadeType.PERSIST)
    private List<Cart> cartList = new ArrayList<>();
    @JsonManagedReference
    @OneToMany(mappedBy = "member", cascade = CascadeType.PERSIST)
    private List<Heart> heartList = new ArrayList<>();
    @JsonManagedReference
    @OneToMany(mappedBy = "member", cascade = CascadeType.PERSIST)
    private List<MemberCoupon> memberCouponList = new ArrayList<>();*/
    public void createMember(LocalDateTime nowDate, Role role, String ... member) {
        this.memberId = member[0];
        this.role = role;
        this.name = member[1];
        this.password = member[2];
        this.nickName = member[3];
        this.email = member[4];
        this.zipCode = member[5];
        this.address = member[6];
        this.detailAddress = member[7];
        this.telNo = member[8];
        this.joinDate = nowDate;
    }

    public Member(){

    }

    @Builder
    public Member(String name, String email, String picture, Role role){
        this.name = name;
        this.email = email;
        this.picture = picture;
        this.role = role;
    }

    public Member update(String ... member) {
        this.name = member[0];
        this.picture = member[1];

        return this;
    }

    public String getRoleKey(){
        return this.role.getKey();
    }
}
