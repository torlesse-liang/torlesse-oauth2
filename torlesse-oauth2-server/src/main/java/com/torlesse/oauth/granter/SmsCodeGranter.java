package com.torlesse.oauth.granter;

import com.torlesse.oauth.granter.auth.TelePhoneAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/03/23/21:05
 * @Description: SmsCodeGranter
 */
@Slf4j
public class SmsCodeGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "sms_code";

    protected final AuthenticationManager authenticationManager;

    public SmsCodeGranter(AuthenticationManager authenticationManager, AuthorizationServerTokenServices tokenServices,
                          ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        Map<String, String> parameters = new LinkedHashMap(tokenRequest.getRequestParameters());
        String telephone = parameters.get("telePhone");
        String code = parameters.get("code");
        //根据传入的手机号从redis中拿code，比较code是否相等
        if(!code.equals("123123")){
            throw new InvalidGrantException("短信验证码填写错误.");
        }
        // 根据手机号码查询用户信息：根据实际情况操作 这里只做演示没有数据库访问操作
        //模拟查询出来的user
        String user = "torlesse";
        if (user == null) {
            throw new InvalidGrantException("手机号码填写错误.");
        }

        Authentication userAuth = new TelePhoneAuthenticationToken(user, "123456", telephone, code);
        ((AbstractAuthenticationToken) userAuth).setDetails(parameters);

        try {
            userAuth = this.authenticationManager.authenticate(userAuth);
        } catch (AccountStatusException var8) {
            throw new InvalidGrantException("当前用户已经被锁定,请联系客服.");
        } catch (BadCredentialsException var9) {
            throw new InvalidGrantException("用户信息查询异常,请确认是否注册.");
        } catch (InternalAuthenticationServiceException var10) {
            throw new InvalidGrantException("验证码校验失败.");
        }

        if (userAuth != null && userAuth.isAuthenticated()) {
            OAuth2Request storedOAuth2Request = this.getRequestFactory().createOAuth2Request(client, tokenRequest);
            return new OAuth2Authentication(storedOAuth2Request, userAuth);
        } else {
            throw new InvalidGrantException("Could not authenticate user: " + telephone);
        }

    }
}
