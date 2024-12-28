package com.shop.domain.enums;

public enum PaymentType {
    CARD("Card", "카드"),
    ACCOUNT("Account","계좌이체");
    private final String code;
    private final String value;
    public String getCode(){
        return code;
    }
    public String getValue(){
        return value;
    }
    PaymentType(String code, String value){
        this.code = code;
        this.value = value;
    }
}
