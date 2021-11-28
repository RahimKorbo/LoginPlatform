package com.pf.login.repository;

import com.pf.login.models.ERole;
import com.pf.login.models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);

}
