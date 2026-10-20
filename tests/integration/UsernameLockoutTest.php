<?php
namespace BP\Hardening\Tests;

use BP\Hardening\Username_Lockout;
use PHPUnit\Framework\TestCase;

/**
 * Calls the methods directly on a fresh instance: Plugin::boot() has already registered
 * the site's own instance on the hooks.
 */
final class UsernameLockoutTest extends TestCase {

	private Username_Lockout $lock;

	protected function setUp(): void {
		$this->lock = new Username_Lockout();
	}

	protected function tearDown(): void {
		$_COOKIE = [];
	}

	public static function tearDownAfterClass(): void {
		Fixtures::clean();
	}

	public function test_four_failures_leave_the_username_open_and_the_fifth_locks_it(): void {
		$username = Fixtures::identifier( 'bp-victim-' . wp_generate_password( 8, false ) );

		$this->fail_times( $username, 4 );
		$this->assertFalse( is_wp_error( $this->lock->check_lock( null, $username ) ) );

		$this->fail_times( $username, 1 );
		$locked = $this->lock->check_lock( null, $username );
		$this->assertTrue( is_wp_error( $locked ) );
		$this->assertSame( 'bp_login_locked', $locked->get_error_code() );
	}

	public function test_a_locked_username_refuses_even_the_right_password(): void {
		$user = Fixtures::user();
		Fixtures::identifier( $user->user_login );

		$this->fail_times( $user->user_login, 5 );

		$this->assertTrue( is_wp_error( $this->lock->check_lock( $user, $user->user_login ) ) );
	}

	public function test_a_successful_login_clears_the_lock_on_the_login_and_on_the_email(): void {
		$user = Fixtures::user();
		Fixtures::identifier( $user->user_login );
		Fixtures::identifier( $user->user_email );

		$this->fail_times( $user->user_login, 5 );
		$this->fail_times( $user->user_email, 5 );
		$this->lock->on_success( $user->user_login, $user );

		$this->assertFalse( is_wp_error( $this->lock->check_lock( null, $user->user_login ) ) );
		$this->assertFalse( is_wp_error( $this->lock->check_lock( null, $user->user_email ) ) );
	}

	public function test_single_site_administrators_are_not_exempt(): void {
		$admin = Fixtures::user( 'administrator' );
		Fixtures::identifier( $admin->user_login );

		$this->fail_times( $admin->user_login, 5 );

		$this->assertTrue( is_wp_error( $this->lock->check_lock( null, $admin->user_login ) ) );
	}

	public function test_a_browser_that_logged_in_before_is_exempt(): void {
		$user = Fixtures::user();
		Fixtures::identifier( $user->user_login );
		$this->fail_times( $user->user_login, 5 );

		$this->give_device_cookie( $user, time() + HOUR_IN_SECONDS );

		$this->assertFalse( is_wp_error( $this->lock->check_lock( $user, $user->user_login ) ) );
	}

	public function test_a_forged_or_expired_device_cookie_is_not_exempt(): void {
		$user = Fixtures::user();
		Fixtures::identifier( $user->user_login );
		$this->fail_times( $user->user_login, 5 );

		$_COOKIE[ 'bp_known_device_' . $user->ID ] = $user->ID . '|' . ( time() + HOUR_IN_SECONDS ) . '|' . str_repeat( 'a', 64 );
		$this->assertTrue( is_wp_error( $this->lock->check_lock( $user, $user->user_login ) ), 'forged' );

		$this->give_device_cookie( $user, time() - 1 );
		$this->assertTrue( is_wp_error( $this->lock->check_lock( $user, $user->user_login ) ), 'expired' );
	}

	public function test_a_password_change_invalidates_device_cookies(): void {
		$user = Fixtures::user();
		Fixtures::identifier( $user->user_login );
		$this->fail_times( $user->user_login, 5 );
		$this->give_device_cookie( $user, time() + HOUR_IN_SECONDS );

		wp_set_password( wp_generate_password( 24 ), $user->ID );
		clean_user_cache( $user->ID );

		$this->assertTrue( is_wp_error( $this->lock->check_lock( $user, $user->user_login ) ) );
	}

	public function test_a_lockout_is_reported_with_a_pseudonym_never_the_username(): void {
		$username = Fixtures::identifier( 'bp-victim-' . wp_generate_password( 8, false ) );
		$events   = [];
		$listener = static function ( string $event, array $context ) use ( &$events ): void {
			$events[] = [ $event, $context ];
		};
		add_action( 'bp/hardening/event', $listener, 10, 2 );

		try {
			$this->fail_times( $username, 5 );
		} finally {
			remove_action( 'bp/hardening/event', $listener, 10 );
		}

		$this->assertSame( 'lockout', $events[0][0] ?? null );
		$this->assertStringNotContainsString( $username, (string) wp_json_encode( $events ) );
	}

	private function fail_times( string $username, int $times ): void {
		for ( $i = 0; $i < $times; $i++ ) {
			$this->lock->on_fail( $username );
		}
	}

	private function give_device_cookie( \WP_User $user, int $expires ): void {
		$sign = new \ReflectionMethod( Username_Lockout::class, 'device_signature' );

		$_COOKIE[ 'bp_known_device_' . $user->ID ] = $user->ID . '|' . $expires . '|' . $sign->invoke( $this->lock, $user->ID, $expires );
	}
}
