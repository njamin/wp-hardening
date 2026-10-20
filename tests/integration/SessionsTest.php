<?php
namespace BP\Hardening\Tests;

use PHPUnit\Framework\TestCase;

final class SessionsTest extends TestCase {

	public static function tearDownAfterClass(): void {
		Fixtures::clean();
	}

	protected function tearDown(): void {
		wp_set_current_user( 0 );
	}

	public function test_an_administrator_session_lasts_at_most_twelve_hours(): void {
		$admin = Fixtures::user( 'administrator' );

		$this->assertSame( 12 * HOUR_IN_SECONDS, apply_filters( 'auth_cookie_expiration', 14 * DAY_IN_SECONDS, $admin->ID, true ) );
	}

	public function test_other_users_keep_the_lifetime_wordpress_gives(): void {
		$user = Fixtures::user();

		$this->assertSame( 14 * DAY_IN_SECONDS, apply_filters( 'auth_cookie_expiration', 14 * DAY_IN_SECONDS, $user->ID, true ) );
	}

	public function test_a_role_change_ends_every_session(): void {
		$user = Fixtures::user();
		$this->open_sessions( $user, 2 );

		$user->set_role( 'editor' );

		$this->assertCount( 0, \WP_Session_Tokens::get_instance( $user->ID )->get_all() );
	}

	public function test_a_password_reset_ends_every_session(): void {
		$user = Fixtures::user();
		$this->open_sessions( $user, 2 );

		reset_password( $user, wp_generate_password( 24 ) );

		$this->assertCount( 0, \WP_Session_Tokens::get_instance( $user->ID )->get_all() );
	}

	public function test_a_password_changed_by_an_administrator_ends_every_session(): void {
		$user = Fixtures::user();
		$this->open_sessions( $user, 2 );
		wp_set_current_user( Fixtures::user( 'administrator' )->ID );

		wp_update_user( [ 'ID' => $user->ID, 'user_pass' => wp_generate_password( 24 ) ] );

		$this->assertCount( 0, \WP_Session_Tokens::get_instance( $user->ID )->get_all() );
	}

	public function test_a_profile_update_without_a_new_password_keeps_the_sessions(): void {
		$user = Fixtures::user();
		$this->open_sessions( $user, 2 );

		wp_update_user( [ 'ID' => $user->ID, 'display_name' => 'Renamed' ] );

		$this->assertCount( 2, \WP_Session_Tokens::get_instance( $user->ID )->get_all() );
	}

	private function open_sessions( \WP_User $user, int $count ): void {
		$tokens = \WP_Session_Tokens::get_instance( $user->ID );
		for ( $i = 0; $i < $count; $i++ ) {
			$tokens->create( time() + HOUR_IN_SECONDS );
		}
	}
}
