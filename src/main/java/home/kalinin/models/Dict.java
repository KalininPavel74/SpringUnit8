package home.kalinin.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
@Data
@RequiredArgsConstructor
@Entity
public class Dict {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @Column(unique=true)
    @NotBlank(message = "Error. Name is required")
    private String name;
    @NotNull(message = "Error. Not null value.")
    @Min(value = 0, message = "Error. Value > 0 required.")
    private double number;
    public Dict(String name, double number) {
        this.name = name;
        this.number = number;
    }
}
