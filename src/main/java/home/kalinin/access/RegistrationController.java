package home.kalinin.access;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/registration")
@Slf4j
public class RegistrationController {
  
  private User1Repository userRepo;
  private PasswordEncoder passwordEncoder;

  public RegistrationController(
          User1Repository userRepo, PasswordEncoder passwordEncoder) {
    this.userRepo = userRepo;
    this.passwordEncoder = passwordEncoder;
  }
  
  @GetMapping
  public String registerForm() {
    return "registration";
  }
  
  @PostMapping
  public String processRegistration(RegistrationUser1 form) {
    log.info("post form="+form);
    userRepo.save(form.toUser(passwordEncoder));
    log.info("post userRepo.save(form.toUser(passwordEncoder));");
    return "redirect:/login";
  }

}
