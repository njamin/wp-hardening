<?php
namespace BP\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Only the file types the project declares can be uploaded.
 *
 * The default is images and PDF. A project widens it with the
 * `bp/hardening/upload_mimes` filter; SVG is accepted only once
 * `BP_SVG_SANITISER` is set, because an SVG can carry script.
 */
final class Uploads {

	private const DEFAULT_MIMES = [
		'jpg|jpeg|jpe' => 'image/jpeg',
		'png'          => 'image/png',
		'gif'          => 'image/gif',
		'webp'         => 'image/webp',
		'avif'         => 'image/avif',
		'pdf'          => 'application/pdf',
	];

	public function register(): void {
		// Late, so a plugin that adds types on the default priority is still overruled.
		add_filter( 'upload_mimes', [ $this, 'allowed_mimes' ], 99 );
	}

	/**
	 * @return array<string, string>
	 */
	public function allowed_mimes(): array {
		$mimes = (array) apply_filters( 'bp/hardening/upload_mimes', self::DEFAULT_MIMES );

		if ( ! ( defined( 'BP_SVG_SANITISER' ) && BP_SVG_SANITISER ) ) {
			$mimes = array_filter( $mimes, static fn( string $mime ): bool => ! str_contains( $mime, 'svg' ) );
		}

		return $mimes;
	}
}
