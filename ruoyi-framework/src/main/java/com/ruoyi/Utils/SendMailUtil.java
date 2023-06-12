package com.ruoyi.Utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Component
public class SendMailUtil {


    @Value("${spring.mail.username}")
    private String fromMail;

    @Autowired
    JavaMailSender mailSender;

    public void sendMail(String subject,String toMail, String text)  {
       MimeMessage message = mailSender.createMimeMessage();
        try {
            MimeMessageHelper messageHelper = new MimeMessageHelper(message,true);
            messageHelper.setSubject(subject);
            messageHelper.setText(text);
            messageHelper.setTo(toMail);
            messageHelper.setFrom(fromMail);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
        mailSender.send(message);
    }
}
