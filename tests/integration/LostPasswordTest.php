<?php
namespace BP\Hardening\Tests;

use BP\Hardening\Rate_Limit;
use PHPUnit\Framework\TestCase;

final class LostPasswordTest extends TestCase {

	private const IP = '198.51.100.78';

	private array $server;

	private int $mails = 0;

	protected function setUp(): void {
		$this->server           = $_SERVER;
		$_SERVER['REMOTE_ADDR'] = self::IP;
		Rate_Limit::reset( 'lost_password', self::IP );

		$this->mails = 0;
		add_filter( 'pre_wp_mail', [ $this, 'count_mail' ] );
	}

	protected function tearDown(): void {
		remove_filter( 'pre_wp_mail', [ $this, 'count_mail' ] );
		Rate_Limit::reset( 'lost_password', self::IP );
		$_SERVER = $this->server;
	}

	public static function tearDownAfterClass(): void {
		Fixtures::clean();
	}

	public function count_mail(): bool {
		++$this->mails;

		return true;
	}

	public function test_a_known_account_gets_the_email(): void {
		$this->assertTrue( retrieve_password( Fixtures::user()->user_login ) );
		$this->assertSame( 1, $this->mails );
	}

	public function test_an_unknown_username_gets_the_same_answer_as_a_sent_email(): void {
		$this->assertRedirectsToConfirm( 'bp-nobody-' . wp_generate_password( 6, false ) );
	}

	public function test_an_unknown_email_gets_the_same_answer_as_a_sent_email(): void {
		// Core adds its "no account with that e-mail" error before our hook runs.
		$this->assertRedirectsToConfirm( 'bp-nobody-' . wp_generate_password( 6, false ) . '@example.test' );
	}

	public function test_an_empty_field_still_gets_its_own_error(): void {
		$result = retrieve_password( '' );

		$this->assertTrue( is_wp_error( $result ) );
		$this->assertSame( 'empty_username', $result->get_error_code() );
	}

	public function test_over_the_limit_a_known_account_gets_the_same_answer_but_no_email(): void {
		$user = Fixtures::user();
		for ( $i = 0; $i < 5; $i++ ) {
			retrieve_password( $user->user_login );
		}
		$this->assertSame( 5, $this->mails );

		$this->assertRedirectsToConfirm( $user->user_login );
		$this->assertSame( 5, $this->mails );
	}

	public function test_a_mail_failure_gets_the_same_answer_as_a_sent_email(): void {
		remove_filter( 'pre_wp_mail', [ $this, 'count_mail' ] );
		add_filter( 'pre_wp_mail', '__return_false' );
		try {
			$errors = retrieve_password( Fixtures::user()->user_login );
		} finally {
			remove_filter( 'pre_wp_mail', '__return_false' );
		}
		$this->assertSame( 'retrieve_password_email_failure', $errors->get_error_code(), 'core reports the failure' );

		// What wp-login.php does with it before showing the form again.
		try {
			do_action( 'lost_password', $errors );
			$this->fail( 'Expected the "e-mail sent" redirect.' );
		} catch ( Redirect_Exception $redirect ) {
			$this->assertStringContainsString( 'checkemail=confirm', $redirect->location );
		}
	}

	private function assertRedirectsToConfirm( string $login ): void {
		try {
			retrieve_password( $login );
			$this->fail( 'Expected the "e-mail sent" redirect.' );
		} catch ( Redirect_Exception $redirect ) {
			$this->assertStringContainsString( 'checkemail=confirm', $redirect->location );
		}
	}
}
