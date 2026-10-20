<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The visitor's IP address, trusting a proxy header only from a declared proxy.
 *
 * `BP_TRUSTED_PROXIES` lists the edge provider's published ranges (CIDR), and
 * `BP_CLIENT_IP_HEADER` names its header (default `X-Forwarded-For`).
 */
final class Client_Ip {

	public static function get(): string {
		$remote = self::valid( $_SERVER['REMOTE_ADDR'] ?? '' );

		// Behind an edge, REMOTE_ADDR is the edge itself; a header from anyone else is forgeable.
		if ( '' === $remote || ! self::is_trusted( $remote ) ) {
			return $remote;
		}

		$header = defined( 'BP_CLIENT_IP_HEADER' ) ? (string) BP_CLIENT_IP_HEADER : 'HTTP_X_FORWARDED_FOR';
		$chain  = array_map( 'trim', explode( ',', (string) wp_unslash( $_SERVER[ $header ] ?? '' ) ) );

		// Read right to left: each trusted hop appended the address it received from.
		foreach ( array_reverse( $chain ) as $hop ) {
			$ip = self::valid( $hop );
			if ( '' !== $ip && ! self::is_trusted( $ip ) ) {
				return $ip;
			}
		}

		return $remote;
	}

	public static function is_trusted( string $ip ): bool {
		$ranges = defined( 'BP_TRUSTED_PROXIES' ) ? (array) BP_TRUSTED_PROXIES : [];

		foreach ( $ranges as $range ) {
			if ( self::in_range( $ip, (string) $range ) ) {
				return true;
			}
		}

		return false;
	}

	public static function in_range( string $ip, string $cidr ): bool {
		[ $subnet, $bits ] = array_pad( explode( '/', $cidr, 2 ), 2, null );

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( (string) $subnet );
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$max  = strlen( $ip_bin ) * 8;
		$bits = null === $bits ? $max : max( 0, min( (int) $bits, $max ) );
		$full = intdiv( $bits, 8 );
		if ( substr( $ip_bin, 0, $full ) !== substr( $subnet_bin, 0, $full ) ) {
			return false;
		}

		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = chr( ( 0xff << ( 8 - $rest ) ) & 0xff );

		return ( $ip_bin[ $full ] & $mask ) === ( $subnet_bin[ $full ] & $mask );
	}

	private static function valid( string $ip ): string {
		return false !== filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}
}
