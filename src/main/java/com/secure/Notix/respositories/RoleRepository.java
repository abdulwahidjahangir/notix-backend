package com.secure.Notix.respositories;


import com.secure.Notix.models.AppRole;
import com.secure.Notix.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);
}
