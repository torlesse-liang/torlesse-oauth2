package com.torlesse.oauth.model;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Created with IntelliJ IDEA.
 *
 * @Author: torlesse-liang
 * @Date: 2022/04/11/22:36
 * @Description: User实体类
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@TableName("t_user")
public class UserInfo implements Serializable {

    /**
     * 用户名
     */
    @TableField(value = "username")
    private String username;

    /**
     * 密码
     */
    @TableField(value = "password")
    private String password;

    /**
     * 手机号
     */
    @TableField(value = "telephone")
    private String telephone;

    /**
     * 是否有效
     */
    @TableField(value = "enabled")
    private Integer enabled;

}
