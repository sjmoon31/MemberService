package com.shop.domain.enums;

public enum SizeType implements BaseEnum {
    XL("XL", "엑스라지", ProductType.OUTER),
    L("L", "라지", ProductType.OUTER),
    M("M", "미디움", ProductType.OUTER),
    S("S", "스몰", ProductType.OUTER);
    private final String code;
    private final String value;
    private final ProductType parentProductType;
    SizeType(String code, String value, ProductType parentProductType){
        this.code = code;
        this.value = value;
        this.parentProductType = parentProductType;
    }
    public String getCode(){
        return code;
    }
    public String getValue(){
        return value;
    }
}
