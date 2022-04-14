package com.torlesse.oauth;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/22:00
 * @Description: Oauth2ServerApplication授权服务器启动类
 */
@SpringBootApplication
@MapperScan(basePackages = "com.torlesse.oauth.dao")
public class Oauth2ServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(Oauth2ServerApplication.class, args);
    }
}
