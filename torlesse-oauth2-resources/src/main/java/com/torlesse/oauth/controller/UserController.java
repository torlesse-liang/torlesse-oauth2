package com.torlesse.oauth.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/22:50
 * @Description: HelloController
 */
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private TokenStore tokenStore;

    /***
     * 管理员可访问，返回登录用户名
     * @param authentication
     * @return
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/name")
    public String name(OAuth2Authentication authentication) {
        return authentication.getName();
    }

    /**
     * 超级管理员可访问，返回登录用户信息
     *
     * @param authentication
     * @return
     */
    @PreAuthorize("hasRole('ROLE_SUPER_ADMIN')")
    @GetMapping
    public OAuth2Authentication testRoleSuperAdmin(OAuth2Authentication authentication) {
        return authentication;
    }

    /**
     * 只有ROLE_ADMIN权限可以访问，返回访问令牌中的额外信息
     * @param authentication
     * @return
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping
    public Object testRoleAdmin(OAuth2Authentication authentication) {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
        OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());
        return accessToken.getAdditionalInformation().getOrDefault("userDetails", null);
    }
}
