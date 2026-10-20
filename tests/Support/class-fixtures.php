<?php
namespace BP\Hardening\Tests;

/**
 * Users and transients a test creates, removed in tearDownAfterClass().
 */
final class Fixtures {

	/** @var list<int> */
	private static array $users = [];

	/** @var list<string> */
	private static array $transients = [];

	public static function user( string $role = 'subscriber' ): \WP_User {
		$login = 'bp-test-' . wp_generate_password( 8, false );
		$id    = wp_insert_user(
			[
				'user_login' => $login,
				'user_email' => $login . '@example.test',
				'user_pass'  => wp_generate_password( 24 ),
				'role'       => $role,
			]
		);
		if ( is_wp_error( $id ) ) {
			throw new \RuntimeException( $id->get_error_message() );
		}

		self::$users[] = $id;

		return get_userdata( $id );
	}

	/**
	 * Remembers a username or e-mail whose lockout transients must go.
	 */
	public static function identifier( string $identifier ): string {
		self::$transients[] = $identifier;

		return $identifier;
	}

	public static function clean(): void {
		foreach ( self::$transients as $identifier ) {
			$hash = \BP\Hardening\Security_Event::pseudonym( $identifier );
			delete_transient( 'bp_login_fails_' . $hash );
			delete_transient( 'bp_login_lock_' . $hash );
		}
		foreach ( self::$users as $id ) {
			wp_delete_user( $id );
		}

		self::$users      = [];
		self::$transients = [];
	}
}
