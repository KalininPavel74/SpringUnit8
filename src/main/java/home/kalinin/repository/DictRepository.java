package home.kalinin.repository;

import home.kalinin.models.Dict;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
public interface DictRepository extends JpaRepository<Dict, Long> { }
