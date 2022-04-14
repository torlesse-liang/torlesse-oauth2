package com.torlesse.oauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/23:14
 * @Description: HelloController
 */
@RestController
@RequestMapping("/test")
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "访问客户端自身的资源";
    }

}
