package com.secure.Notix.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender javaMailSender;

    public void sendPasswordResetEmail(String to, String resetUrl) {
        try {
            SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
            simpleMailMessage.setTo(to);
            simpleMailMessage.setSubject("Password Reset Request");
            simpleMailMessage.setText("Click to reset your password: " + resetUrl);

            javaMailSender.send(simpleMailMessage);

            System.out.println("Email sent successfully to: " + to);
        } catch (Exception e) {
            System.out.println("Failed to send email to: " + to);
            e.printStackTrace();
        }
    }
}
