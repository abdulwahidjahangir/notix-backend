package com.secure.Notix.respositories;

import com.secure.Notix.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserName(String userName);

    Boolean existsByEmail(String email);
    Boolean existsByUserName(String userName);

    Optional<User> findByEmail(String email);
}
