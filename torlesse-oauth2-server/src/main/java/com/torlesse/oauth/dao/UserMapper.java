package com.torlesse.oauth.dao;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.torlesse.oauth.model.UserInfo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/22:35
 * @Description: UserMapper
 */
@Mapper
public interface UserMapper extends BaseMapper<UserInfo> {

    /**
     * 根据用户名查询用户
     *
     * @param username
     * @return
     */
    @Select("select username,password,enabled from t_user where username = #{username} and enabled = 1")
    UserInfo queryUserByUserName(@Param("username") String username);
}
