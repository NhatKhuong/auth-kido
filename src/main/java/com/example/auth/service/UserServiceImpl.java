package com.example.auth.service;

import com.example.auth.dto.request.ChangePasswordRequest;
import com.example.auth.dto.response.AccountResponse;
import com.example.auth.entity.User;
import com.example.auth.exception.InvalidCurrentPasswordException;
import com.example.auth.exception.UnauthorizedException;
import com.example.auth.mapper.AccountMapper;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Account read and password change of architecture 01-overview.md section 2.3.
 *
 * <p>Both flows resolve the account from the id in the verified access token. The password change
 * verifies {@code currentPassword} with the configured {@link PasswordEncoder} — the same bean
 * login uses, so the two can never disagree about what a stored hash means — and stores only the
 * encoded form of the replacement.
 */
@Service
public class UserServiceImpl implements UserService {

	private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	@Transactional(readOnly = true)
	public AccountResponse getCurrentAccount(Long userId) {
		return AccountMapper.toAccountResponse(requireAccount(userId));
	}

	@Override
	@Transactional
	public void changePassword(Long userId, ChangePasswordRequest request) {
		User user = requireAccount(userId);

		if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
			// Username only: neither the attempted nor the new password may reach a log file.
			log.info("Rejected password change for username '{}': current password did not match",
					user.getUsername());
			throw new InvalidCurrentPasswordException();
		}

		// Encoded here, never in the controller: hashing is a business rule of this flow, and the
		// entity's contract is that password_hash only ever receives PasswordEncoder output.
		user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
		// Explicit save even though the entity is managed: it states the intent, and it is what a
		// unit test with a mocked repository can observe.
		userRepository.save(user);

		log.info("Password changed for username '{}'", user.getUsername());
	}

	/**
	 * Resolves the account the access token names.
	 *
	 * <p>The token's signature was already verified, so a missing row means the account was removed
	 * while a token for it was still live: the credential is stale, which is a 401 and not a 404
	 * (see {@link UnauthorizedException}).
	 */
	private User requireAccount(Long userId) {
		return userRepository.findWithRolesAndPermissionsById(userId)
				.orElseThrow(() -> {
					log.info("Rejected request: access token names account id {} which no longer exists", userId);
					return new UnauthorizedException("Account no longer exists");
				});
	}
}
