package com.torlesse.oauth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/23:16
 * @Description: DemoController 用于模拟场景
 *  1、单点登录场景
 *  2、客户端访问受保护资源场景
 */
@RestController
@RequestMapping("/demo")
public class DemoController {
    @Autowired
    OAuth2RestTemplate restTemplate;

    /**
     * 用于单点登录测试
     * @param authentication
     * @return
     */
    @GetMapping("/userInfoPage")
    public ModelAndView securedPage(OAuth2Authentication authentication) {
        return new ModelAndView("userInfoPage").addObject("authentication", authentication);
    }

    /**
     * 访问受保护资源
     * @return
     */
    @GetMapping("/remoteCall")
    public String remoteCall() {
        ResponseEntity<String> responseEntity = restTemplate.getForEntity("http://localhost:8081/user/name", String.class);
        return responseEntity.getBody();
    }
}
