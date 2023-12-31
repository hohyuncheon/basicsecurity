package io.security.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BasicSecurityController {

    @GetMapping("/")
    public String index(){
        return "home";
    }

    @GetMapping("loginPage")
    public String loginPAge(){
        return "loginPage";
    }

    @GetMapping("user")
    public String user(){
        return "user";
    }
    @GetMapping("admin/pay")
    public String adminPay(){
        return "adminPay";
    }

    @GetMapping("admin/**")
    public String admin(){
        return "admin";
    }

    @GetMapping("denied")
    public String denied(){
        return "denied";
    }

    @GetMapping("login")
    public String login(){
        return "login";
    }
}
