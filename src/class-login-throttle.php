<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Per-IP limit on failed logins, so brute force is throttled even with no edge provider.
 *
 * `BP_LOGIN_IP_LIMIT` failures (20) within `BP_LOGIN_IP_WINDOW` (600 s) block that IP
 * until the window ends. The IP comes from Client_Ip, so behind an edge it is the
 * visitor's, not the edge's.
 */
final class Login_Throttle {

	private const BUCKET = 'login_ip';

	public function register(): void {
		// Priority 30: after the username lockout (25), so a locked username keeps its own message.
		add_filter( 'authenticate', [ $this, 'check' ], 30 );
		add_action( 'wp_login_failed', [ $this, 'count_failure' ] );
	}

	public function check( mixed $user ): mixed {
		$ip = Client_Ip::get();
		if ( '' === $ip || ! Rate_Limit::exceeded( self::BUCKET, $ip, $this->limit() ) ) {
			return $user;
		}

		return new \WP_Error(
			'bp_login_throttled',
			esc_html__( 'Too many login attempts. Please try again later.', 'bp-hardening' )
		);
	}

	public function count_failure(): void {
		$ip = Client_Ip::get();
		if ( '' === $ip ) {
			return;
		}

		$window = defined( 'BP_LOGIN_IP_WINDOW' ) ? (int) BP_LOGIN_IP_WINDOW : 10 * MINUTE_IN_SECONDS;
		if ( Rate_Limit::count( self::BUCKET, $ip, $window ) === $this->limit() ) {
			Security_Event::emit( 'login_ip_throttled' );
		}
	}

	private function limit(): int {
		return defined( 'BP_LOGIN_IP_LIMIT' ) ? (int) BP_LOGIN_IP_LIMIT : 20;
	}
}
