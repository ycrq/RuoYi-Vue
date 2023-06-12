package com.ruoyi.system.domain;

import lombok.Data;

@Data
public class Template {

    /**
     * 模板Id
     */
    private int TemplateId;

    /**
     * 主题
     */
    private String subject;

    /**
     * 内容
     */
    private String text;
}
