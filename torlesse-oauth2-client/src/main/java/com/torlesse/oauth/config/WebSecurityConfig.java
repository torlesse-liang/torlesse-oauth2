package com.torlesse.oauth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/23:20
 * @Description: spring security配置
 */
@Configuration
@Order(200)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * /路径和/login路径允许访问，其它路径需要身份认证后才能访问
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers( "/demo**","/login**")
                .permitAll()
                .antMatchers("/test/hello")
                .anonymous()
                .anyRequest()
                .authenticated();
    }
}
