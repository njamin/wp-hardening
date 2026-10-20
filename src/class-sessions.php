<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shorter sessions for administrators (`BP_ADMIN_SESSION_LIFETIME`, 12 h), and every
 * session of a user ended when their password or role changes.
 */
final class Sessions {

	public function register(): void {
		add_filter( 'auth_cookie_expiration', [ $this, 'admin_lifetime' ], 10, 2 );
		add_action( 'after_password_reset', [ $this, 'end_sessions_of' ] );
		add_action( 'profile_update', [ $this, 'on_profile_update' ], 10, 2 );
		add_action( 'set_user_role', [ $this, 'end_sessions_of' ] );
		add_action( 'add_user_role', [ $this, 'end_sessions_of' ] );
		add_action( 'remove_user_role', [ $this, 'end_sessions_of' ] );
	}

	public function admin_lifetime( int $length, int $user_id ): int {
		if ( ! user_can( $user_id, 'manage_options' ) ) {
			return $length;
		}

		$max = defined( 'BP_ADMIN_SESSION_LIFETIME' ) ? (int) BP_ADMIN_SESSION_LIFETIME : 12 * HOUR_IN_SECONDS;

		return min( $length, $max );
	}

	public function on_profile_update( int $user_id, \WP_User $old_user ): void {
		$user = get_userdata( $user_id );
		if ( $user && $user->user_pass !== $old_user->user_pass ) {
			$this->end_sessions_of( $user_id );
		}
	}

	public function end_sessions_of( mixed $user ): void {
		$user_id  = $user instanceof \WP_User ? $user->ID : (int) $user;
		$sessions = \WP_Session_Tokens::get_instance( $user_id );

		// A user changing their own password keeps the session they are using.
		if ( get_current_user_id() === $user_id && '' !== wp_get_session_token() ) {
			$sessions->destroy_others( wp_get_session_token() );
			return;
		}

		$sessions->destroy_all();
	}
}
