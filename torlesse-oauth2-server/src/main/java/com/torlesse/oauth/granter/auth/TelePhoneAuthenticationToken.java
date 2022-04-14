package com.torlesse.oauth.granter.auth;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/03/23/21:20
 * @Description: 手机验证码token
 */
public class TelePhoneAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private String telePhone;

    private String code;

    /**
     * @param principal 用户名
     */
    public TelePhoneAuthenticationToken(Object principal, Object credentials, String telePhone, String code) {
        super(principal, credentials);
        setAuthenticated(false);
        this.telePhone = telePhone;
        this.code = code;
    }

    public String getTelePhone() {
        return telePhone;
    }

    public String getCode() {
        return code;
    }
}