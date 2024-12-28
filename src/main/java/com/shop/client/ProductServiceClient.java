package com.shop.client;

import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(name="ProductProject")
public interface ProductServiceClient {

}
