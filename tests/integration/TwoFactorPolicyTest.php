<?php
namespace BP\Hardening\Tests;

use BP\Hardening\Two_Factor_Policy;
use PHPUnit\Framework\TestCase;

final class TwoFactorPolicyTest extends TestCase {

	/** @var list<int> */
	private array $users = [];

	protected function tearDown(): void {
		remove_all_filters( 'bp/hardening/two_factor_roles' );
		require_once ABSPATH . 'wp-admin/includes/user.php';
		foreach ( $this->users as $user ) {
			wp_delete_user( $user );
		}
	}

	public function test_a_project_adds_its_own_roles_to_those_that_must_enrol(): void {
		$this->requires_two_factor();
		$author = $this->user( 'author', 'twofa-' );

		$this->assertFalse( ( new Two_Factor_Policy() )->must_enrol( $author ), 'Not one of the default roles.' );

		add_filter( 'bp/hardening/two_factor_roles', static fn( array $roles ): array => [ ...$roles, 'author' ] );

		$this->assertTrue( ( new Two_Factor_Policy() )->must_enrol( $author ) );
	}

	public function test_a_filter_returning_only_its_own_roles_still_leaves_the_administrator_enrolled(): void {
		$this->requires_two_factor();
		add_filter( 'bp/hardening/two_factor_roles', static fn(): array => [ 'author' ] );

		$this->assertTrue( ( new Two_Factor_Policy() )->must_enrol( $this->user( 'administrator', 'twofa-' ) ) );
	}

	public function test_an_exemption_ending_in_a_star_exempts_every_login_it_starts(): void {
		$exempt = [ 'site-admin', 'e2e-*' ];

		$this->assertTrue( Two_Factor_Policy::exempts( 'site-admin', $exempt ) );
		$this->assertTrue( Two_Factor_Policy::exempts( 'e2e-bureau-1a2b3c', $exempt ) );
		$this->assertFalse( Two_Factor_Policy::exempts( 'site-admin-2', $exempt ), 'A login without a star is exact.' );
		$this->assertFalse( Two_Factor_Policy::exempts( 'x-e2e-bureau', $exempt ), 'A star entry matches the start only.' );
		$this->assertFalse( Two_Factor_Policy::exempts( 'anyone', [ '*' ] ), 'A bare star exempts nobody.' );
	}

	private function requires_two_factor(): void {
		if ( ! class_exists( '\Two_Factor_Core' ) ) {
			$this->markTestSkipped( 'The Two Factor plugin is not active on this site.' );
		}
	}

	private function user( string $role, string $prefix ): \WP_User {
		$id = wp_insert_user(
			[
				'user_login' => $prefix . wp_generate_password( 6, false ),
				'user_pass'  => wp_generate_password(),
				'role'       => $role,
			]
		);
		$this->assertIsInt( $id );
		$this->users[] = $id;

		return new \WP_User( $id );
	}
}
