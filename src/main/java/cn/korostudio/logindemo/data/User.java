package cn.korostudio.logindemo.data;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;

@Data
@Entity
public class User {
    @Id
    String UUID;
    String username;
    String password;
}
