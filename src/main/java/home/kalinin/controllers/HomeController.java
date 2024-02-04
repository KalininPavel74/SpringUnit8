package home.kalinin.controllers;

import home.kalinin.access.User1Repository;
import home.kalinin.access.security.User1;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/home")
@AllArgsConstructor
@Slf4j
public class HomeController {
    private User1Repository user1Repository;

    private record User1Short(String username, String fullname, String roles) {}
    @GetMapping
    public String getHome(Model model){
        //log.info("!! HomeController");
        List<User1Short> usersShort = new ArrayList<>();
        for(User1 user: user1Repository.findAll())
            usersShort.add(new User1Short(user.getUsername(),user.getFullname(), user.getAuthorities().toString()));
        model.addAttribute("users", usersShort);
        //log.info("!! HomeController "+usersShort);
        return "home";
    }
}