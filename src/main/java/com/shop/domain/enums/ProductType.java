package com.shop.domain.enums;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum ProductType implements BaseEnum {
    OUTER("O", "아우터", null),
        CARDIGAN("Cardigan", "카디건", OUTER),
        COAT("Coat", "코트", OUTER),
        JACKET("Jacket", "자켓", OUTER),
        PADDING("Padding", "패딩", OUTER),
        PARKA("Parka", "파카", OUTER),
    TOP("T","상의", null),
        NEAT("Neat", "니트", TOP),
        TEE("Tee", "티셔츠", TOP),
        SHIRT("Shirt", "셔츠", TOP),
    PANTS("P","바지", null),
        COTTON_PANTS( "Cotton_Pants", "면바지", PANTS),
        DENIM_PANTS("Denim_Pants","데님바지", PANTS),
        TRAINING_PANTS("Training_Pants", "트레이닝바지", PANTS),
    SHOES("S","신발", null),
        BOOTS("Boots","부츠", SHOES),
        RUNNING_SHOES("Running_Shoes","운동화", SHOES),
        DERBY_SHOES("Derby_Shoes","구두", SHOES),
    ACCESSORIES("A","악세사리", null),
        BAG("Bag","가방", ACCESSORIES),
        NECKLACE("Necklace","목걸이", ACCESSORIES),
        WATCH("Watch","시계", ACCESSORIES);
    private final String code;
    private final String value;
    private final ProductType parentProductType;
    private final List<ProductType> childProductTypes;

    private static final Map<String,String> codeMap
            = Collections.unmodifiableMap(Stream.of(values()).collect(Collectors.toMap(ProductType::getCode, ProductType::name)));

    ProductType(String code, String value, ProductType parentProductType){
        this.code = code;
        this.value = value;
        this.parentProductType = parentProductType;
        this.childProductTypes = new ArrayList<>();
        if(Objects.nonNull(parentProductType)) {
            parentProductType.childProductTypes.add(this);
        }
    }
    public String getCode(){
        return code;
    }
    public String getValue(){
        return value;
    }
    // 부모카테고리 Getter
    public Optional<ProductType> getParentCategory() {
        return Optional.ofNullable(parentProductType);
    }
    // 자식카테고리 Getter
    public List<ProductType> getChildCategories() {
        return Collections.unmodifiableList(childProductTypes);
    }
    public static ProductType of(String code){
        return ProductType.valueOf(codeMap.get(code));
    }
}
