package home.kalinin.controllers;

import home.kalinin.models.Dict;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import home.kalinin.repository.DictRepository;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(path = "/api", produces = "application/json")
@AllArgsConstructor
@Slf4j
public class DictRestController {
    /**
     * Репозиторий заметок
     */
    private final DictRepository dictRepository;

    /**
     * Получение полного перечная заметок.
     * @return Список заметок, упакованный в полноценный http формат.
     */
    @GetMapping()
    public ResponseEntity<List<Dict>> getAllTasks() {
        return new ResponseEntity<>(dictRepository.findAll(), HttpStatus.OK);
    }

    /**
     * Получение данных по указанной заметке.
     * @param id - код заметки
     * @return Искомая заметока, упакованная в полноценный http формат.
     */
    @GetMapping("/{id}")
    public ResponseEntity<Dict> getTask(@PathVariable Long id) {
        if(id == null || id <= 0)
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        Optional<Dict> oTask = dictRepository.findById(id);
        if (oTask.isEmpty())
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        return new ResponseEntity<>(oTask.get(), HttpStatus.OK);
    }

    /**
     * Удаление указанной заметки.
     * @param id - код заметки
     * @return код удаленной заметки, упакованный в полноценный http формат.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Long> deleteTask(@PathVariable Long id) {
        if(id == null || id <= 0)
            return new ResponseEntity<>(id, HttpStatus.BAD_REQUEST);
        try {
            dictRepository.deleteById(id);
        } catch (DataAccessException ex) {
            log.error("DataAccessException ");
            log.error(ex.getLocalizedMessage());
            return new ResponseEntity<>(id, HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(id, HttpStatus.OK);
    }

    /**
     * Добавление новой заметки
     * @param dict - добавляемая заметка
     * @return Добавленная заметка, упакованная в полноценный http формат.
     */
    @PostMapping
    public ResponseEntity<Dict> addTask(@RequestBody Dict dict) {
        if (dict == null)
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        try {
            dictRepository.save(dict);
        } catch (DataAccessException ex) {
            log.error("DataAccessException ");
            log.error(ex.getLocalizedMessage());
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(dict, HttpStatus.CREATED);
    }

    /**
     * Заменить заметку с указанным кодом на новую.
     * @param id - код ЗАМЕНЯЕМОЙ заметки.
     * @param dict - заметка, все поля которой, заменят существующую заметку с кодом id
     * @return замененная заметка, упакованная в полноценный http формат.
     */
    @PutMapping("/{id}")
    public ResponseEntity<Dict> updateTask(
            @PathVariable Long id, @RequestBody Dict dict) {
        if(id == null || id <= 0 || dict == null)
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        dict.setId(id);
        try {
            dictRepository.save(dict);
        } catch (DataAccessException ex) {
            log.error("DataAccessException ");
            log.error(ex.getLocalizedMessage());
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(dict, HttpStatus.CREATED);
    }

    /**
     * Обновление (замена) данных полей указанной заметки.
     * @param id - код заметки, в которая будет частично обновлена
     * @param dict - заметка содержащая обновленные поля для замены
     * @return обновленная заметка с кодом id, упакованная в полноценный http формат.
     */
    @PatchMapping("/{id}")
    public ResponseEntity<Dict> updateSelectiveFieldsTask(
            @PathVariable Long id, @RequestBody Dict dict) {
        if(id == null || id <= 0 || dict == null)
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        Optional<Dict> oTask = dictRepository.findById(id);
        if (oTask.isEmpty())
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        Dict existDict = oTask.get();
        if (dict.getName() != null && !dict.getName().isBlank())
            existDict.setName(dict.getName());
        existDict.setNumber(dict.getNumber());
        try {
            dictRepository.save(existDict);
        } catch (DataAccessException ex) {
            log.error("DataAccessException ");
            log.error(ex.getLocalizedMessage());
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(existDict, HttpStatus.OK);
    }
}