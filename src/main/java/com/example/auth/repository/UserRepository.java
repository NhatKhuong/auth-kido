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

	/**
	 * Loads the account by id together with its roles and permissions in one query.
	 *
	 * <p>The id, not the username, is the key: an authenticated request already carries the id in
	 * its access token, so no second lookup by name is needed. The entity graph is here for the
	 * same reason as on {@link #findByUsername(String)} — the account response needs both
	 * collections after the transaction has closed.
	 */
	@EntityGraph(attributePaths = { "roles", "roles.permissions" })
	Optional<User> findWithRolesAndPermissionsById(Long id);

	boolean existsByUsername(String username);
}
