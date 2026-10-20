<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The lost-password form answers the same for an existing and an unknown account, and
 * is rate limited per IP (`BP_LOST_PASSWORD_LIMIT` requests per hour, default 5).
 * That holds when the e-mail can't be sent too: core would say so, but only for a real account.
 */
final class Lost_Password {

	public function register(): void {
		add_action( 'lostpassword_post', [ $this, 'handle' ], 10, 2 );
		add_action( 'lost_password', [ $this, 'hide_mail_failure' ] );
	}

	/**
	 * Core shows "the e-mail could not be sent" only when the account exists. The failure is
	 * an event for whoever runs the site, and the visitor gets the usual answer.
	 */
	public function hide_mail_failure( \WP_Error $errors ): void {
		if ( in_array( 'retrieve_password_email_failure', $errors->get_error_codes(), true ) ) {
			Security_Event::emit( 'lost_password_mail_failed' );
			$this->answer_as_sent();
		}
	}

	public function handle( \WP_Error $errors, mixed $user_data ): void {
		$limit = defined( 'BP_LOST_PASSWORD_LIMIT' ) ? (int) BP_LOST_PASSWORD_LIMIT : 5;
		$ip    = Client_Ip::get();

		if ( '' !== $ip && ! Rate_Limit::hit( 'lost_password', $ip, $limit, HOUR_IN_SECONDS ) ) {
			Security_Event::emit( 'lost_password_throttled' );
			$this->answer_as_sent();
		}

		// An empty field reveals nothing; let WordPress say so.
		if ( $user_data instanceof \WP_User || in_array( 'empty_username', $errors->get_error_codes(), true ) ) {
			return;
		}

		// No account. Core has already added `invalid_email` by now, so the errors can't be
		// returned: answer exactly as WordPress does after sending the e-mail.
		$this->answer_as_sent();
	}

	private function answer_as_sent(): never {
		$redirect = ! empty( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : 'wp-login.php?checkemail=confirm'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the core form has no nonce; this only mirrors its redirect
		wp_safe_redirect( $redirect );
		exit;
	}
}
