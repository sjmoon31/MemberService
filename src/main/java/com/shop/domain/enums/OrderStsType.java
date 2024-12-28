package com.shop.domain.enums;

public enum OrderStsType {
    ORDER_COMPLETE("Order_Complete", "주문완료"),
    PRODUCT_READY("Product_Ready", "물품준비중"),
    DELIVERY("Delivery","배송중"),
    DELIVERY_COMPLETE("Delivery_Complete","배송완료"),
    REFUND_REQUEST("Refund_Request","환불신청"),
    REFUND("Refund","환불");
    private final String code;
    private final String value;
    public String getCode(){
        return code;
    }
    public String getValue(){
        return value;
    }
    OrderStsType(String code, String value){
        this.code = code;
        this.value = value;
    }
}
