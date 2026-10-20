<?php
namespace BP\Hardening\Tests;

use BP\Hardening\Client_Ip;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The bootstrap declares 10.0.0.0/8 as the trusted proxy range.
 */
final class ClientIpTest extends TestCase {

	private array $server;

	protected function setUp(): void {
		$this->server = $_SERVER;
	}

	protected function tearDown(): void {
		$_SERVER = $this->server;
	}

	public function test_a_header_from_an_untrusted_address_is_ignored(): void {
		$_SERVER['REMOTE_ADDR']          = '203.0.113.5';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.9';

		$this->assertSame( '203.0.113.5', Client_Ip::get() );
	}

	public function test_behind_a_trusted_proxy_the_visitor_address_comes_from_the_header(): void {
		$_SERVER['REMOTE_ADDR']          = '10.1.2.3';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.9';

		$this->assertSame( '198.51.100.9', Client_Ip::get() );
	}

	public function test_the_chain_is_read_right_to_left_so_a_spoofed_first_entry_is_skipped(): void {
		$_SERVER['REMOTE_ADDR']          = '10.1.2.3';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 198.51.100.9, 10.0.0.7';

		$this->assertSame( '198.51.100.9', Client_Ip::get() );
	}

	public function test_a_garbage_header_falls_back_to_the_proxy_address(): void {
		$_SERVER['REMOTE_ADDR']          = '10.1.2.3';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = 'not-an-ip, <script>';

		$this->assertSame( '10.1.2.3', Client_Ip::get() );
	}

	#[DataProvider( 'ranges' )]
	public function test_range_matching( string $ip, string $cidr, bool $expected ): void {
		$this->assertSame( $expected, Client_Ip::in_range( $ip, $cidr ) );
	}

	/**
	 * @return array<string, array{string, string, bool}>
	 */
	public static function ranges(): array {
		return [
			'ipv4 inside'            => [ '203.0.113.7', '203.0.113.0/24', true ],
			'ipv4 outside'           => [ '198.51.100.1', '203.0.113.0/24', false ],
			'ipv4 odd prefix inside' => [ '203.0.113.130', '203.0.113.128/25', true ],
			'ipv4 odd prefix out'    => [ '203.0.113.127', '203.0.113.128/25', false ],
			'ipv6 inside'            => [ '2001:db8::1', '2001:db8::/32', true ],
			'ipv6 outside'           => [ '2001:db9::1', '2001:db8::/32', false ],
			'mixed families'         => [ '203.0.113.7', '2001:db8::/32', false ],
			'single address'         => [ '203.0.113.7', '203.0.113.7', true ],
			'prefix too long'        => [ '203.0.113.7', '203.0.113.7/99', true ],
			'not an address'         => [ 'nope', '203.0.113.0/24', false ],
		];
	}
}
