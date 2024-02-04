package home.kalinin.controllers;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import home.kalinin.models.Dict;
import home.kalinin.repository.DictRepository;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@EnableMethodSecurity  // для @PreAuthorize("hasRole('ADMIN')") подходят обе
//@EnableGlobalMethodSecurity(prePostEnabled = true)   // для @PreAuthorize("hasRole('ADMIN')") подходят обе  УСТАРЕЛА
@RequestMapping("/admin")
@AllArgsConstructor
@Slf4j
public class AdminController {
    private final DictRepository dictRepository;
//    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public String getAdmin(Model model) {
        model.addAttribute("dicts", dictRepository.findAll());
        return "admin";
    }

    @PreAuthorize("hasRole('ADMIN')")  // в месте с @EnableMethodSecurity на классе
    @PostMapping("/deleteAll")
    public String addDict(Model model) {
        log.info("POST AdminController deleteAll");
        try {
            dictRepository.deleteAll();
        } catch (DataAccessException ex) {
            log.error("DataAccessException ");
            log.error(ex.getLocalizedMessage());
            model.addAttribute("db_save_error", ex.getMessage());
        }
        model.addAttribute("dicts", dictRepository.findAll());
        return "redirect:/admin";
    }
}