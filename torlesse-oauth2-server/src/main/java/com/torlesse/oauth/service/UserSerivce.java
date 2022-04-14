package com.torlesse.oauth.service;

import com.torlesse.oauth.model.UserInfo;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/22:40
 * @Description: UserSerivce
 */
public interface UserSerivce {

    /**
     * 根据用户名查询用户信息
     *
     * @param username
     * @return
     */
    public UserInfo queryByUserName(String username);
}
