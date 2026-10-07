package com.example.auth.repository;

import com.example.auth.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

	/**
	 * Loads the account together with its roles and permissions in one query.
	 *
	 * <p>The entity graph is what keeps authentication from issuing a query per role: the caller
	 * runs outside a transaction once the user is returned, so lazy collections would otherwise
	 * fail or trigger N+1.
	 */
	@EntityGraph(attributePaths = { "roles", "roles.permissions" })
	Optional<User> findByUsername(String username);

	boolean existsByUsername(String username);
}
