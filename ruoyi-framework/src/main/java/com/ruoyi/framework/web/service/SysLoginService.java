package com.ruoyi.framework.web.service;

import javax.annotation.Resource;


import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.core.util.StrUtil;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.ruoyi.Utils.SendMailUtil;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.exception.CustomException;
import com.ruoyi.framework.smsConfig.SmsCodeAuthenticationToken;

import com.ruoyi.mailConfig.MailCodeAuthenticationToken;
import com.ruoyi.system.domain.Template;

import com.ruoyi.system.service.TemplateService;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import com.ruoyi.common.constant.CacheConstants;
import com.ruoyi.common.constant.Constants;
import com.ruoyi.common.constant.UserConstants;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.core.redis.RedisCache;
import com.ruoyi.common.exception.ServiceException;
import com.ruoyi.common.exception.user.BlackListException;
import com.ruoyi.common.exception.user.CaptchaException;
import com.ruoyi.common.exception.user.CaptchaExpireException;
import com.ruoyi.common.exception.user.UserNotExistsException;
import com.ruoyi.common.exception.user.UserPasswordNotMatchException;
import com.ruoyi.common.utils.DateUtils;
import com.ruoyi.common.utils.MessageUtils;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.common.utils.ip.IpUtils;
import com.ruoyi.framework.manager.AsyncManager;
import com.ruoyi.framework.manager.factory.AsyncFactory;
import com.ruoyi.framework.security.context.AuthenticationContextHolder;
import com.ruoyi.system.service.ISysConfigService;
import com.ruoyi.system.service.ISysUserService;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 登录校验方法
 * 
 * @author ruoyi
 */
@Component
public class SysLoginService
{
    @Autowired
    private TokenService tokenService;

    @Resource
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;
    
    @Autowired
    private ISysUserService userService;

    @Autowired
    private ISysConfigService configService;

    @Autowired
    private TemplateService templateService;

    @Autowired
    private SendMailUtil sendMailUtil;

    //接口用常量值定义
    private int mailCodeLength = 6;
    private int redisDuration = 86400;
    private long redisLimit = 15;

    /**
     * 邮件验证码 redis key
     */
    public static final String MAIL_CAPTCHA_CODE_KEY = "mail_captcha_code:";

    /**
     * 邮件验证码发送限制 redis key
     */
    public static final String MAIL_CAPTCHA_CODE_LIMIT_KEY = "mail_captcha_code_limit:";

    /**
     * 邮件验证码过期时间 10分钟
     */
    public static final Integer MAIL_EXPIRATION = 10*60;

    /**
     * 邮件获取限制时间 1分钟
     */
    public static final Integer MAIL_SEND_RATE_TIME = 60;

    /**
     * 邮件获取速率限制 redis key
     */
    public static final String MAIL_SEND_RATE_KEY = "mail_send_rate:";

    /**
     * 验证码验证次数限制
     */
    public static final String MAIl_CODE_LOCK_TIME = "mail_code_lock_time:";


    /**
     * 邮箱验证码登录
     * @param email 邮箱
     * @param captcha 验证码
     * @return
     */
    public AjaxResult loginByMail(String email, String captcha){

        // 用户验证
        Authentication authentication = null;
        try
        {
            if(!checkMailCode(email, captcha)){
                String codeLockKey = new StringBuffer(MAIl_CODE_LOCK_TIME).append(email).toString();
                Long count = redisCache.incr(codeLockKey);
                if (count == 1){
                    redisCache.expire(codeLockKey,MAIL_EXPIRATION,TimeUnit.SECONDS);
                }
                if (count > 5){
                    String mailKey= new StringBuffer(MAIL_CAPTCHA_CODE_KEY).append(email).toString();
                    redisCache.deleteObject(mailKey);
                    redisCache.deleteObject(codeLockKey);
                    return AjaxResult.error(0,"验证码已失效，请重新获取验证码");
                }
                return AjaxResult.error(0,"验证码错误");
            }
            // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
            authentication = authenticationManager
                    .authenticate(new MailCodeAuthenticationToken(email));
        }
        catch (Exception e)
        {

            AsyncManager.me().execute(AsyncFactory.recordLogininfor(email, Constants.LOGIN_FAIL, e.getMessage()));
            throw new CustomException(e.getMessage());

        }
        AsyncManager.me().execute(AsyncFactory.recordLogininfor(email, Constants.LOGIN_SUCCESS, MessageUtils.message("user.login.success")));
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        AjaxResult ajax = AjaxResult.success();

        // 生成token
        String token = tokenService.createToken(loginUser);
        ajax.put(Constants.TOKEN, token);
        return  ajax;
    }

    public boolean checkMailCode(String email, String captcha){
        String mailKey = new StringBuffer(MAIL_CAPTCHA_CODE_KEY).append(email).toString();
        if (!redisCache.hasKey(mailKey)){
            return false;
        }
        if(captcha.equals(redisCache.getCacheObject(mailKey))) {
            //验证通过删除验证码，删除获取速率限制
            String rateKey = new StringBuffer(MAIL_SEND_RATE_KEY).append(email).toString();
            redisCache.deleteObject(mailKey);
            redisCache.deleteObject(rateKey);
            return true;
        }
        return false;
    }


    /**
     * 登录验证
     * 
     * @param username 用户名
     * @param password 密码
     * @param code 验证码
     * @param uuid 唯一标识
     * @return 结果
     */
    public String login(String username, String password,String code, String uuid)
    {

        // 验证码校验
        validateCaptcha(username, code, uuid);
        // 登录前置校验
        loginPreCheck(username, password);
        // 用户验证
        Authentication authentication = null;
        try
        {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
            AuthenticationContextHolder.setContext(authenticationToken);
            // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
            authentication = authenticationManager.authenticate(authenticationToken);
        }
        catch (Exception e)
        {
            if (e instanceof BadCredentialsException)
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
                throw new UserPasswordNotMatchException();
            }
            else
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, e.getMessage()));
                throw new ServiceException(e.getMessage());
            }
        }
        finally
        {
            AuthenticationContextHolder.clearContext();
        }
        AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_SUCCESS, MessageUtils.message("user.login.success")));
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        recordLoginInfo(loginUser.getUserId());
        // 生成token
        return tokenService.createToken(loginUser);
    }

    /**
     * 校验验证码
     * 
     * @param username 用户名
     * @param code 验证码
     * @param uuid 唯一标识
     * @return 结果
     */
    public void validateCaptcha(String username, String code, String uuid)
    {
        boolean captchaEnabled = configService.selectCaptchaEnabled();
        if (captchaEnabled)
        {
            String verifyKey = CacheConstants.CAPTCHA_CODE_KEY + StringUtils.nvl(uuid, "");
            String captcha = redisCache.getCacheObject(verifyKey);
            redisCache.deleteObject(verifyKey);
            if (captcha == null)
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.jcaptcha.expire")));
                throw new CaptchaExpireException();
            }
            if (!code.equalsIgnoreCase(captcha))
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.jcaptcha.error")));
                throw new CaptchaException();
            }
        }
    }

    /**
     * 登录前置校验
     * @param username 用户名
     * @param password 用户密码
     */
    public void loginPreCheck(String username, String password)
    {
        // 用户名或密码为空 错误
        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password))
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("not.null")));
            throw new UserNotExistsException();
        }
        // 密码如果不在指定范围内 错误
        if (password.length() < UserConstants.PASSWORD_MIN_LENGTH
                || password.length() > UserConstants.PASSWORD_MAX_LENGTH)
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
            throw new UserPasswordNotMatchException();
        }
        // 用户名不在指定范围内 错误
        if (username.length() < UserConstants.USERNAME_MIN_LENGTH
                || username.length() > UserConstants.USERNAME_MAX_LENGTH)
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
            throw new UserPasswordNotMatchException();
        }
        // IP黑名单校验
        String blackStr = configService.selectConfigByKey("sys.login.blackIPList");
        if (IpUtils.isMatchedIp(blackStr, IpUtils.getIpAddr()))
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("login.blocked")));
            throw new BlackListException();
        }
    }

    /**
     * 记录登录信息
     *
     * @param userId 用户ID
     */
    public void recordLoginInfo(Long userId)
    {
        SysUser sysUser = new SysUser();
        sysUser.setUserId(userId);
        sysUser.setLoginIp(IpUtils.getIpAddr());
        sysUser.setLoginDate(DateUtils.getNowDate());
        userService.updateUserProfile(sysUser);
    }

    /**
     * 发送邮箱验证码
     */
    public AjaxResult sendMailCaptcha(String email,int templateId) {

        String rateKey = new StringBuffer(MAIL_SEND_RATE_KEY).append(email).toString();
        if (!StrUtil.isEmpty(redisCache.getCacheObject(rateKey))){
            return AjaxResult.error("操作频繁，请一分钟后再试");
        }else{
            redisCache.expire(rateKey,MAIL_SEND_RATE_TIME,TimeUnit.SECONDS);
        }
        String limitKey = new StringBuffer(MAIL_CAPTCHA_CODE_LIMIT_KEY).append(email).toString();
        if (!checkOperaTimes(redisLimit,redisDuration,limitKey)){
            return AjaxResult.error("今日发送次数已达最大限制");
        }

        Template template = templateService.getOne(new QueryWrapper<Template>().lambda()
                .eq(Template::getTemplateId,templateId));
        if(ObjectUtil.isNull(template)){//模板不存在
            return AjaxResult.error("发送邮件失败");
        }
        String subject = template.getSubject();
        String captcha = RandomUtil.randomNumbers(mailCodeLength);
        //渲染邮件模板
        Map<String,String> paramMap = new HashMap<>();
        paramMap.put("mailCaptcha",captcha);
        String text = StrUtil.format(template.getText(),paramMap);
        sendMailUtil.sendMail(subject,email,text);
        String mailKey = new StringBuffer(MAIL_CAPTCHA_CODE_KEY).append(email).toString();
        redisCache.setCacheObject(mailKey,captcha,MAIL_EXPIRATION, TimeUnit.SECONDS);
        return AjaxResult.success("发送验证码成功");
    }

    /**
     * 发送手机验证码
     */
    public AjaxResult sendSmsCaptcha(String email,int templateId){

        return null;
    }

    /**
     * 手机号登录验证
     *
     * @param mobile 手机号
     * @param code 验证码
     * @param uuid 唯一标识
     * @return 结果
     */

    public AjaxResult smsLogin(String mobile, String code, String uuid)
    {

        // 用户验证
        Authentication authentication = null;
        try
        {
            checkSmsCode(mobile,code,uuid);

            // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
            authentication = authenticationManager
                    .authenticate(new SmsCodeAuthenticationToken(mobile));
        }
        catch (Exception e)
        {

            AsyncManager.me().execute(AsyncFactory.recordLogininfor(mobile, Constants.LOGIN_FAIL, e.getMessage()));
            throw new CustomException(e.getMessage());

        }
        AsyncManager.me().execute(AsyncFactory.recordLogininfor(mobile, Constants.LOGIN_SUCCESS, MessageUtils.message("user.login.success")));
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        AjaxResult ajax = AjaxResult.success();

        // 生成token
        String token = tokenService.createToken(loginUser);
        ajax.put(Constants.TOKEN, token);
        return  ajax;
    }

    /**
     * 检查手机号登录
     * @param
     */
    private void checkSmsCode(String mobile,String inputCode, String uuid) {

        String verifyKey = Constants.SMS_CAPTCHA_CODE_KEY + uuid;

        Map<String, Object> smsCode =  redisCache.getCacheObject(verifyKey);
//        redisCache.deleteObject(verifyKey);
        if(StringUtils.isEmpty(inputCode)){
            throw new BadCredentialsException("验证码不能为空");
        }

        if(smsCode == null) {
            throw new BadCredentialsException("验证码失效");
        }

        String applyMobile = (String) smsCode.get("mobile");
        String code =  (String) smsCode.get("code");

        if(!applyMobile.equals(mobile)) {
            throw new BadCredentialsException("手机号码不一致");
        }
        if(!code.equals(inputCode)) {
            throw new BadCredentialsException("验证码错误");
        }
    }

    /**
     * 操作次数限制检查
     * @param limit
     * @param duration
     * @param operaKey
     * @return
     */
    private boolean checkOperaTimes(Long limit, Integer duration, String operaKey){
        Long operaCount = redisCache.incr(operaKey);
        if (operaCount == 1){
            redisCache.expire(operaKey,duration,TimeUnit.SECONDS);
        }
        if (operaCount > limit){
            return false;
        }
        return true;
    }
}