package com.ruoyi;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.ruoyi.system.domain.Template;
import com.ruoyi.system.mapper.TemplateMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;



@SpringBootTest
public class MybatisPlusTest {

    @Autowired
    private TemplateMapper templateMapper;

    @Test
    void test(){
        Template template = new Template();
        QueryWrapper qw = new QueryWrapper();
        qw.eq("template_id",1);
        template = templateMapper.selectOne(qw);
        System.out.println(template.getSubject()+":"+template.getText());
    }


}
