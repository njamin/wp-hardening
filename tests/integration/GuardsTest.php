<?php
namespace BP\Hardening\Tests;

use BP\Hardening\Honeypot;
use BP\Hardening\Plugin_Guard;
use BP\Hardening\Security_Event;
use BP\Hardening\Two_Factor_Policy;
use PHPUnit\Framework\TestCase;

/**
 * Uploads, the plugin guard, forced 2FA, the honeypot and pseudonyms. The bootstrap
 * protects `two-factor/two-factor.php` and exempts the login `bp-test-admin`.
 */
final class GuardsTest extends TestCase {

	public static function tearDownAfterClass(): void {
		Fixtures::clean();
	}

	protected function tearDown(): void {
		$_POST = [];
	}

	public function test_uploads_accept_images_and_pdf_only_by_default(): void {
		$mimes = apply_filters( 'upload_mimes', [ 'exe' => 'application/x-msdownload', 'svg' => 'image/svg+xml' ] );

		$this->assertSame( [ 'jpg|jpeg|jpe', 'png', 'gif', 'webp', 'avif', 'pdf' ], array_keys( $mimes ) );
	}

	public function test_a_project_can_add_types_but_svg_needs_a_sanitiser(): void {
		$add = static fn( array $mimes ): array => $mimes + [ 'csv' => 'text/csv', 'svg' => 'image/svg+xml' ];
		add_filter( 'bp/hardening/upload_mimes', $add );

		try {
			$mimes = apply_filters( 'upload_mimes', [] );
		} finally {
			remove_filter( 'bp/hardening/upload_mimes', $add );
		}

		$this->assertArrayHasKey( 'csv', $mimes );
		$this->assertArrayNotHasKey( 'svg', $mimes );
	}

	public function test_a_protected_plugin_is_put_back_when_wp_admin_deactivates_it(): void {
		$old = [ 'two-factor/two-factor.php', 'other/other.php' ];

		$kept = ( new Plugin_Guard() )->keep_protected_active( [ 'other/other.php' ], $old );

		$this->assertEqualsCanonicalizing( $old, $kept );
	}

	public function test_other_plugins_can_be_deactivated(): void {
		$kept = ( new Plugin_Guard() )->keep_protected_active( [ 'two-factor/two-factor.php' ], [ 'two-factor/two-factor.php', 'other/other.php' ] );

		$this->assertSame( [ 'two-factor/two-factor.php' ], $kept );
	}

	public function test_a_protected_plugin_has_no_deactivate_link(): void {
		$links = ( new Plugin_Guard() )->remove_deactivate_link( [ 'deactivate' => 'x', 'settings' => 'y' ], 'two-factor/two-factor.php' );

		$this->assertSame( [ 'settings' ], array_keys( $links ) );
	}

	public function test_an_editor_without_two_factor_must_enrol(): void {
		$this->assertTrue( ( new Two_Factor_Policy() )->must_enrol( Fixtures::user( 'editor' ) ) );
	}

	public function test_a_subscriber_need_not_enrol(): void {
		$this->assertFalse( ( new Two_Factor_Policy() )->must_enrol( Fixtures::user() ) );
	}

	public function test_an_editor_who_must_enrol_is_sent_to_their_profile(): void {
		wp_set_current_user( Fixtures::user( 'editor' )->ID );
		$GLOBALS['pagenow'] = 'index.php';

		try {
			( new Two_Factor_Policy() )->require_enrolment();
			$this->fail( 'Expected a redirect to the profile.' );
		} catch ( Redirect_Exception $redirect ) {
			$this->assertStringContainsString( 'profile.php', $redirect->location );
		} finally {
			wp_set_current_user( 0 );
		}
	}

	public function test_the_test_admin_is_exempt_on_local(): void {
		$this->assertSame( 'local', wp_get_environment_type(), 'The suite runs against the local sandbox.' );

		$id = wp_insert_user( [ 'user_login' => 'bp-test-admin', 'user_pass' => wp_generate_password( 24 ), 'role' => 'administrator' ] );
		try {
			$this->assertFalse( ( new Two_Factor_Policy() )->must_enrol( get_userdata( $id ) ) );
		} finally {
			wp_delete_user( $id );
		}
	}

	public function test_the_honeypot_catches_a_filled_field_and_lets_an_empty_one_through(): void {
		$this->assertStringContainsString( 'name="bp_website"', Honeypot::field() );

		$_POST['bp_website'] = '';
		$this->assertFalse( Honeypot::is_bot() );

		$_POST['bp_website'] = 'https://spam.example';
		$this->assertTrue( Honeypot::is_bot() );
	}

	public function test_a_pseudonym_is_keyed_so_a_plain_hash_of_the_username_does_not_match(): void {
		$this->assertNotSame( hash( 'sha256', 'alice' ), Security_Event::pseudonym( 'alice' ) );
		$this->assertSame( Security_Event::pseudonym( 'Alice ' ), Security_Event::pseudonym( 'alice' ) );
	}
}
