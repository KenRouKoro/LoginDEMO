package cn.korostudio.logindemo.sql;

import cn.korostudio.logindemo.data.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, String> {
    User findByUsername(String username);
    User findByUUID(String uuid);
}
