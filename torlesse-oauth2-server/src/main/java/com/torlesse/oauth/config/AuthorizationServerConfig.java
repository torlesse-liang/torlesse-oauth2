package com.torlesse.oauth.config;

import com.torlesse.oauth.granter.SmsCodeGranter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/22:01
 * @Description: 授权服务器配置
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private JksProperties jksProperties;

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 用来配置客户端详情服务（ClientDetailsService）
     * 允许客户端自己申请ClientID
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource);
    }

    /**
     * 允许ClientSecret明文方式保存并且可以通过表单提交
     *
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("permitAll()").allowFormAuthenticationForClients().passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    /**
     * AuthorizationServerEndpointsConfigurer：用来配置令牌（token）的访问端点和令牌服务(tokenservices)
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        //添加自定义 token增强
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), jwtTokenEnhancer()));
        // 初始化所有的TokenGranter，并且类型为CompositeTokenGranter
        List<TokenGranter> tokenGranters = getDefaultTokenGranters(endpoints);
        endpoints.approvalStore(approvalStore())
                .authorizationCodeServices(authorizationCodeServices())
                .tokenGranter(new CompositeTokenGranter(tokenGranters))
                .tokenStore(tokenStore())
                .tokenEnhancer(tokenEnhancerChain)
                .authenticationManager(authenticationManager);
    }

    /**
     * 自定义的Token增强器，把更多信息放入Token中
     *
     * @return
     */
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new EnhanceTokenEnhancer();
    }

    /**
     * 配置JWT令牌使用非对称加密方式来验证
     *
     * @return
     */
    @Bean
    protected JwtAccessTokenConverter jwtTokenEnhancer() {
        //设置jwt的转换器
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();

        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                //设置加密的加载文件
                new ClassPathResource(jksProperties.getName()),
                //设置读取秘钥库文件的密码
                jksProperties.getStorePassword().toCharArray());

        //设置获取秘钥的密码
//        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(jksProperties.getAlias());
        //设置获取秘钥的密码
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair("jwt");
        //设置秘钥对象
        converter.setKeyPair(keyPair);
        return converter;
    }

    /**
     * 使用JDBC数据库方式来保存用户的授权批准记录
     *
     * @return
     */
    @Bean
    public JdbcApprovalStore approvalStore() {
        return new JdbcApprovalStore(dataSource);
    }

    /**
     * 使用JDBC数据库方式来保存授权码
     *
     * @return
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new JdbcAuthorizationCodeServices(dataSource);
    }

    /**
     * 使用JWT令牌存储
     *
     * @return
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtTokenEnhancer());
    }

    /**
     * 初始化所有的TokenGranter
     */
    private List<TokenGranter> getDefaultTokenGranters(AuthorizationServerEndpointsConfigurer endpoints) {

        ClientDetailsService clientDetails = endpoints.getClientDetailsService();
        AuthorizationServerTokenServices tokenServices = endpoints.getTokenServices();
        AuthorizationCodeServices authorizationCodeServices = endpoints.getAuthorizationCodeServices();
        OAuth2RequestFactory requestFactory = endpoints.getOAuth2RequestFactory();

        List<TokenGranter> tokenGranters = new ArrayList<>();
        tokenGranters.add(new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices, clientDetails,
                requestFactory));
        tokenGranters.add(new RefreshTokenGranter(tokenServices, clientDetails, requestFactory));
        ImplicitTokenGranter implicit = new ImplicitTokenGranter(tokenServices, clientDetails, requestFactory);
        tokenGranters.add(implicit);
        tokenGranters.add(new ClientCredentialsTokenGranter(tokenServices, clientDetails, requestFactory));
        if (authenticationManager != null) {
            tokenGranters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices,
                    clientDetails, requestFactory));
            tokenGranters.add(new SmsCodeGranter(authenticationManager, endpoints.getTokenServices(),
                    endpoints.getClientDetailsService(), endpoints.getOAuth2RequestFactory()));
        }
        return tokenGranters;
    }
}
