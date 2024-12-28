package com.shop.client;

import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(name="OrderProject")
public interface OrderServiceClient {

}
