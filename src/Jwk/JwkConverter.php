<?php

declare(strict_types=1);

namespace Nyra\Jwt\Jwk;

use InvalidArgumentException;
use Nyra\Jwt\Base64Url;
use Nyra\Jwt\Key;

use function base64_encode;
use function chr;
use function chunk_split;
use function count;
use function explode;
use function is_string;
use function ltrim;
use function ord;
use function sprintf;
use function strlen;

/**
 * Converts public JWK representations into usable key materials.
 */
final class JwkConverter
{
    /**
     * @param array<string,mixed> $jwk
     */
    public static function toKey(array $jwk, string $algorithm): Key
    {
        return new Key(self::toKeyMaterial($jwk), $algorithm, self::extractKeyId($jwk));
    }

    /**
     * @param array<string,mixed> $jwk
     */
    public static function toKeyMaterial(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;
        if (! is_string($kty)) {
            throw new InvalidArgumentException('JWK must contain string kty.');
        }

        return match ($kty) {
            'oct' => self::convertOct($jwk),
            'RSA' => self::convertRsa($jwk),
            'EC' => self::convertEc($jwk),
            default => throw new InvalidArgumentException(sprintf('Unsupported JWK kty "%s".', $kty)),
        };
    }

    /**
     * @param array<string,mixed> $jwk
     */
    private static function extractKeyId(array $jwk): ?string
    {
        $kid = $jwk['kid'] ?? null;

        return is_string($kid) ? $kid : null;
    }

    /**
     * @param array<string,mixed> $jwk
     */
    private static function convertOct(array $jwk): string
    {
        $k = $jwk['k'] ?? null;
        if (! is_string($k)) {
            throw new InvalidArgumentException('oct JWK must contain string k.');
        }

        return Base64Url::decode($k);
    }

    /**
     * @param array<string,mixed> $jwk
     */
    private static function convertRsa(array $jwk): string
    {
        $n = $jwk['n'] ?? null;
        $e = $jwk['e'] ?? null;
        if (! is_string($n) || ! is_string($e)) {
            throw new InvalidArgumentException('RSA JWK must contain string n and e.');
        }

        $modulus = self::trimInteger(Base64Url::decode($n));
        $exponent = self::trimInteger(Base64Url::decode($e));

        $rsaPublicKey = self::encodeSequence(
            self::encodeInteger($modulus) .
            self::encodeInteger($exponent)
        );

        $algorithmIdentifier = self::encodeSequence(
            self::encodeObjectIdentifier('1.2.840.113549.1.1.1') .
            self::encodeNull()
        );

        $subjectPublicKey = self::encodeBitString($rsaPublicKey);
        $spki = self::encodeSequence($algorithmIdentifier . $subjectPublicKey);

        return self::encodePem('PUBLIC KEY', $spki);
    }

    /**
     * @param array<string,mixed> $jwk
     */
    private static function convertEc(array $jwk): string
    {
        $x = $jwk['x'] ?? null;
        $y = $jwk['y'] ?? null;
        $crv = $jwk['crv'] ?? null;

        if (! is_string($x) || ! is_string($y) || ! is_string($crv)) {
            throw new InvalidArgumentException('EC JWK must contain string crv, x, and y.');
        }

        $curve = self::curveOid($crv);

        $xBin = Base64Url::decode($x);
        $yBin = Base64Url::decode($y);

        $expectedLength = self::curveCoordinateLength($crv);
        if (strlen($xBin) !== $expectedLength || strlen($yBin) !== $expectedLength) {
            throw new InvalidArgumentException(sprintf('EC JWK coordinates must be %d bytes for curve %s.', $expectedLength, $crv));
        }

        $publicKeyPoint = "\x04" . $xBin . $yBin;

        $algorithmIdentifier = self::encodeSequence(
            self::encodeObjectIdentifier('1.2.840.10045.2.1') .
            self::encodeObjectIdentifier($curve)
        );

        $subjectPublicKey = self::encodeBitString($publicKeyPoint);
        $spki = self::encodeSequence($algorithmIdentifier . $subjectPublicKey);

        return self::encodePem('PUBLIC KEY', $spki);
    }

    private static function trimInteger(string $value): string
    {
        $value = ltrim($value, "\x00");
        if ($value === '') {
            return "\x00";
        }

        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return $value;
    }

    private static function encodeInteger(string $value): string
    {
        return "\x02" . self::encodeLength(strlen($value)) . $value;
    }

    private static function encodeSequence(string $value): string
    {
        return "\x30" . self::encodeLength(strlen($value)) . $value;
    }

    private static function encodeNull(): string
    {
        return "\x05\x00";
    }

    private static function encodeBitString(string $value): string
    {
        return "\x03" . self::encodeLength(strlen($value) + 1) . "\x00" . $value;
    }

    private static function encodeObjectIdentifier(string $oid): string
    {
        $parts = explode('.', $oid);
        if (count($parts) < 2) {
            throw new InvalidArgumentException(sprintf('Invalid OID "%s".', $oid));
        }

        $first = (int) $parts[0];
        $second = (int) $parts[1];
        $encoded = chr(40 * $first + $second);

        foreach (array_slice($parts, 2) as $part) {
            $encoded .= self::encodeBase128((int) $part);
        }

        return "\x06" . self::encodeLength(strlen($encoded)) . $encoded;
    }

    private static function encodeBase128(int $value): string
    {
        if ($value === 0) {
            return "\x00";
        }

        $bytes = [];

        while ($value > 0) {
            $bytes[] = $value & 0x7F;
            $value >>= 7;
        }

        $encoded = '';
        for ($i = count($bytes) - 1; $i >= 0; $i--) {
            $byte = $bytes[$i];
            if ($i !== 0) {
                $byte |= 0x80;
            }

            $encoded .= chr($byte);
        }

        return $encoded;
    }

    private static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function encodePem(string $label, string $der): string
    {
        $base64 = base64_encode($der);
        $chunks = chunk_split($base64, 64, "\n");

        return sprintf("-----BEGIN %s-----\n%s-----END %s-----\n", $label, $chunks, $label);
    }

    private static function curveOid(string $curve): string
    {
        return match ($curve) {
            'P-256' => '1.2.840.10045.3.1.7',
            'P-384' => '1.3.132.0.34',
            'P-521' => '1.3.132.0.35',
            'secp256k1' => '1.3.132.0.10',
            default => throw new InvalidArgumentException(sprintf('Unsupported EC curve "%s".', $curve)),
        };
    }

    private static function curveCoordinateLength(string $curve): int
    {
        return match ($curve) {
            'P-256', 'secp256k1' => 32,
            'P-384' => 48,
            'P-521' => 66,
            default => throw new InvalidArgumentException(sprintf('Unsupported EC curve "%s".', $curve)),
        };
    }
}
