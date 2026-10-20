<?php
namespace BP\Hardening\Tests;

/**
 * Thrown instead of redirecting, so a test can assert where the code would have sent the browser.
 */
final class Redirect_Exception extends \RuntimeException {

	public function __construct( public readonly string $location ) {
		parent::__construct( 'Redirect to ' . $location );
	}
}
