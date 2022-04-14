package com.torlesse.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/22:44
 * @Description: 资源服务器
 */
@Configuration
@EnableResourceServer//启动资源服务器
@EnableGlobalMethodSecurity(prePostEnabled = true)//启动注解的方式进行权限控制
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    /**
     * 声明了资源服务器的ID是torlesseservice，声明了资源服务器的TokenStore是JWT
     * @param resources
     * @throws Exception
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
       resources.resourceId("torlesseservice").tokenStore(tokenStore());
    }

    @Bean
    public TokenStore tokenStore(){
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * 配置公钥
     * @return
     */
    @Bean
    protected JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        Resource resource = new ClassPathResource("public.cert");
        String publicKey = null;
        try {
            publicKey = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        converter.setVerifierKey(publicKey);
        return converter;
    }


    /**
     * 配置了除了/user路径之外的请求可以匿名访问
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(HttpMethod.POST,"/user/**").authenticated()
                .antMatchers(HttpMethod.GET,"/user/**").authenticated()
                .anyRequest().permitAll();
    }
}
