package com.torlesse.oauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Date;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/22:55
 * @Description: HelloController
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "HelloController--> hello() 可直接访问";
    }

}
