package com.torlesse.oauth.config;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/23:01
 * @Description: OAuth2Client客户端配置
 */
@Configuration
@EnableOAuth2Sso
public class OAuthClientConfig {
    /**
     * 定义OAuth2RestTemplate
     * 可从配置文件application.yml读取oauth配置注入OAuth2ProtectedResourceDetails
     * @param oAuth2ClientContext
     * @param details
     * @return
     */
    @Bean
    public OAuth2RestTemplate oauth2RestTemplate(OAuth2ClientContext oAuth2ClientContext,
                                                 OAuth2ProtectedResourceDetails details) {
        return new OAuth2RestTemplate(details, oAuth2ClientContext);
    }
}
