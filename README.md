# Nyra JWT Library

A lightweight, modern PHP library for working with JSON Web Tokens (JWT), designed for security, extensibility, and
clear developer ergonomics.

## Features

- **JWT Encoding & Decoding:** Create and validate JWTs, supporting HS256/HS384/HS512 (HMAC), RS256/RS384/RS512 (RSA),
  and ES256/ES384/ES512 (ECDSA).
- **Key Management:** Flexible key handling via `Key` objects, string keys, OpenSSL keys, or X.509 certificates.
  Supports key IDs (`kid`) for key rotation.
- **JWK Support:** Convert JSON Web Key (JWK) representations to usable keys via the built-in `JwkConverter`.
- **Strict Validation:** Verifies token structure, signature, algorithm, and key presence. Throws explicit exceptions
  for invalid tokens, unsupported algorithms, and missing keys.
- **PSR-12 & PSR-4 Compliance:** Clean, namespaced code for easy autoloading and integration.
- **Comprehensive Test Suite:** PHPUnit tests covering all success and failure paths.
- **Zero Dependency (except PHP & OpenSSL):** No external JWT libraries required.
- **Extensible:** Easily add more algorithms, custom claims, or integrate with frameworks.

## Getting Started

### Installation

```bash
composer require nyra-dev/jwt
```

### Usage Example

```php
use Nyra\Jwt\Jwt;
use Nyra\Jwt\Key;

$payload = ['sub' => 'user123', 'exp' => time() + 3600];
$key = new Key('your-secret-key', 'HS256');

$jwt = Jwt::encode($payload, $key);
// Pass $jwt to clients

$decoded = Jwt::decode($jwt, $key);
// $decoded is an object with your claims (e.g., $decoded->sub)
```

### Advanced: Asymmetric Keys & JWK

```php
use Nyra\Jwt\Jwk\JwkConverter;

// Convert a JWK array to a Key object
$jwk = [
    'kty' => 'RSA',
    'n' => 'base64url-encoded-modulus',
    'e' => 'base64url-encoded-exponent',
    'kid' => 'my-key-id'
];
$key = JwkConverter::toKey($jwk, 'RS256');
```

## Project Structure

- `src/` — Library code (`Nyra\Jwt\*`)
- `tests/` — PHPUnit tests (`Nyra\Jwt\Tests\*`)
- `composer.json` — Metadata, autoload, scripts

## Development

- Run tests: `composer test`
- Install dependencies: `composer install`
- Rebuild autoloader: `composer dump-autoload -o`
- Test specific classes/methods:
    - `vendor/bin/phpunit --filter JwtTest`
    - `vendor/bin/phpunit --filter 'JwtTest::testItEncodesAndDecodesHs256Tokens'`

## Coding Standards

- PSR-12 code style, PSR-4 autoloading
- Strict types (`declare(strict_types=1)`)
- StudlyCaps for class names, camelCase for methods/properties
- Exceptions end with `Exception`

## Exception Handling

The library throws specific exceptions for error cases:

- `InvalidTokenStructure`
- `SignatureVerificationFailed`
- `UnsupportedAlgorithm`
- `KeyNotFound`

Catch these to handle JWT errors gracefully.

## License

MIT License. See [LICENSE](LICENSE).

## Contributing

Feel free to open issues and pull requests to improve the library. Follow the coding and testing guidelines described
above.

## Organization

Maintained by [nyra-dev](https://github.com/nyra-dev)