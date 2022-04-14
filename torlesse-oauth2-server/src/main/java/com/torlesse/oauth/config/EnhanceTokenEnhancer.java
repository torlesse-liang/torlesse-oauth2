package com.torlesse.oauth.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/22:21
 * @Description: 自定义token增强器，作用可以在jwt中添加自定义信息
 */
public class EnhanceTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        Authentication userAuthentication = oAuth2Authentication.getUserAuthentication();
        if (userAuthentication != null) {
            Object principal = userAuthentication.getPrincipal();
            //把用户标识以userDetails这个Key加入到JWT的额外信息中去
            Map<String, Object> additionalInfo = new HashMap<>();
            additionalInfo.put("userDetails", principal);
            additionalInfo.put("torlesse", "torlesse");
            ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(additionalInfo);
        }
        return oAuth2AccessToken;
    }
}
