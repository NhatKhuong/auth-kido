package com.example.auth.repository;

import com.example.auth.entity.Role;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

	/** Roles are looked up by name because the name, not the generated id, is the stable contract. */
	@EntityGraph(attributePaths = "permissions")
	Optional<Role> findByName(String name);
}
