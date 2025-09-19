<?php

declare(strict_types=1);

namespace Nyra\Jwt\Tests;

use Nyra\Jwt\Exception\SignatureVerificationFailed;
use Nyra\Jwt\Exception\UnsupportedAlgorithm;
use Nyra\Jwt\Jwk\JwkConverter;
use Nyra\Jwt\Jwt;
use Nyra\Jwt\Key;
use PHPUnit\Framework\TestCase;

use function openssl_pkey_get_details;
use function openssl_pkey_new;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;

final class JwtTest extends TestCase
{
    public function testItEncodesAndDecodesHs256Tokens(): void
    {
        $key = new Key('test-secret', 'HS256');
        $payload = (object) ['sub' => 'alice', 'iat' => 1_695_000_000];

        $token = Jwt::encode($payload, $key);
        $header = null;
        $decoded = Jwt::decode($token, $key, $header);

        self::assertSame($payload->sub, $decoded->sub ?? null);
        self::assertSame($payload->iat, $decoded->iat ?? null);
        self::assertSame('HS256', $header?->alg ?? null);
    }

    public function testItRejectsTamperedPayloads(): void
    {
        $key = new Key('secret', 'HS256');
        $token = Jwt::encode(['sub' => 'alice'], $key);

        $segments = explode('.', $token);
        $segments[1] = 'e30'; // tampered payload ({})
        $tampered = implode('.', $segments);

        $this->expectException(SignatureVerificationFailed::class);
        Jwt::decode($tampered, $key);
    }

    public function testItSelectsKeyByKid(): void
    {
        $keyA = new Key('a-secret', 'HS256', 'key-a');
        $keyB = new Key('b-secret', 'HS256', 'key-b');

        $token = Jwt::encode(['sub' => 'kid-test'], $keyB);

        $keys = [
            'key-a' => $keyA,
            'key-b' => $keyB,
        ];

        $decoded = Jwt::decode($token, $keys);

        self::assertSame('kid-test', $decoded->sub ?? null);
    }

    public function testItSignsAndVerifiesRs256Tokens(): void
    {
        $configuration = [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ];

        $resource = openssl_pkey_new($configuration);
        self::assertNotFalse($resource);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        self::assertArrayHasKey('key', $details);
        $publicKey = $details['key'];

        $token = Jwt::encode(['scope' => 'rs256'], $resource, 'RS256');
        $decoded = Jwt::decode($token, new Key($publicKey, 'RS256'));

        self::assertSame('rs256', $decoded->scope ?? null);
    }

    public function testItSignsAndVerifiesEs256Tokens(): void
    {
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        self::assertNotFalse($resource);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        self::assertArrayHasKey('key', $details);
        $publicKey = $details['key'];

        $token = Jwt::encode(['scope' => 'es256'], $resource, 'ES256');
        $decoded = Jwt::decode($token, new Key($publicKey, 'ES256'));

        self::assertSame('es256', $decoded->scope ?? null);
    }

    public function testItConvertsRsaJwkToKey(): void
    {
        $configuration = [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ];

        $resource = openssl_pkey_new($configuration);
        self::assertNotFalse($resource);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        self::assertArrayHasKey('rsa', $details);
        $rsaDetails = $details['rsa'];

        $jwk = [
            'kty' => 'RSA',
            'n' => $this->base64Url($rsaDetails['n']),
            'e' => $this->base64Url($rsaDetails['e']),
            'kid' => 'rsa-key',
        ];

        $key = JwkConverter::toKey($jwk, 'RS256');

        $token = Jwt::encode(['module' => 'jwk'], $resource, 'RS256', 'rsa-key');
        $decoded = Jwt::decode($token, ['rsa-key' => $key]);

        self::assertSame('jwk', $decoded->module ?? null);
    }

    public function testItRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(UnsupportedAlgorithm::class);
        Jwt::encode(['foo' => 'bar'], new Key('secret', 'none'));
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
