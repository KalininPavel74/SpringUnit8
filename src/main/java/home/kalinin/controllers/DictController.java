package home.kalinin.controllers;

import home.kalinin.aspect.TrackUserAction;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
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
@RequestMapping("/dicts")
@AllArgsConstructor
@Slf4j
public class DictController {
    private final DictRepository dictRepository;
    @ModelAttribute(name = "dict")
    public Dict createDict() {
        return new Dict();
    }
    @TrackUserAction
    @GetMapping
    public String getDicts(Model model){
        //log.info("GET dicts");
        model.addAttribute("dicts", dictRepository.findAll());
        return "dicts";
    }
    @TrackUserAction
    @PostMapping
    public String addDict(@Valid Dict dict, Errors errors, Model model){
        //log.info("POST "+dict);
        if (errors.hasErrors()) {
            log.error("errors.hasErrors() "+errors);
            model.addAttribute("db_save_error", errors);
        } else {
            try {
                dictRepository.save(dict);
            } catch (DataAccessException ex) {
                log.error("DataAccessException ");
                log.error(ex.getLocalizedMessage());
                model.addAttribute("db_save_error", ex.getMessage());
            }
        }
        model.addAttribute("dicts", dictRepository.findAll());
        return "dicts";
    }
}