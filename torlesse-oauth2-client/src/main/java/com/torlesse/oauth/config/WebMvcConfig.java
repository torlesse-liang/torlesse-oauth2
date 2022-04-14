package com.torlesse.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/23:20
 * @Description: mvc配置
 */
@Configuration
@EnableWebMvc
public class WebMvcConfig implements WebMvcConfigurer {

    /**
     * 配置RequestContextListener用于启用session scope的Bean
     *
     * @return
     */
    @Bean
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }

    /**
     * 配置index路径的首页Controller
     * @param registry
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/")
                .setViewName("forward:/index");
        registry.addViewController("/index");
    }
}
