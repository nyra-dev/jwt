<?php

declare(strict_types=1);

namespace Nyra\Jwt;

use ArrayAccess;
use Nyra\Jwt\Exception\InvalidTokenStructure;
use Nyra\Jwt\Exception\KeyNotFound;
use Nyra\Jwt\Exception\SignatureVerificationFailed;
use Nyra\Jwt\Exception\UnsupportedAlgorithm;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use stdClass;

use function array_is_list;
use function array_key_exists;
use function chr;
use function count;
use function explode;
use function hash_equals;
use function hash_hmac;
use function implode;
use function is_array;
use function is_object;
use function is_string;
use function ltrim;
use function openssl_sign;
use function openssl_verify;
use function ord;
use function sprintf;
use function str_pad;
use function strlen;
use function strtoupper;
use function substr;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;

final class Jwt
{
    /**
     * @param array<mixed>|object $payload
     * @param Key|string|OpenSSLAsymmetricKey|OpenSSLCertificate $key
     * @param array<string,mixed>|null $headers
     */
    public static function encode(array|object $payload, Key|string|OpenSSLAsymmetricKey|OpenSSLCertificate $key, string $algorithm = 'HS256', ?string $keyId = null, ?array $headers = null): string
    {
        if ($key instanceof Key) {
            $algorithm = $key->algorithm();
            $keyId ??= $key->keyId();
            $keyMaterial = $key->material();
        } else {
            $keyMaterial = $key;
        }

        $algorithm = strtoupper($algorithm);
        if ($algorithm === 'NONE') {
            throw new UnsupportedAlgorithm('The "none" algorithm is not supported.');
        }

        $header = ['typ' => 'JWT', 'alg' => $algorithm];
        if ($headers !== null) {
            $header = $headers + $header;
            $header['alg'] = $algorithm;
        }

        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }

        $encodedHeader = Base64Url::encode(Json::encode((object) $header));
        $encodedPayload = Base64Url::encode(Json::encode($payload));

        $signature = self::sign("$encodedHeader.$encodedPayload", $keyMaterial, $algorithm);
        $encodedSignature = Base64Url::encode($signature);

        return implode('.', [$encodedHeader, $encodedPayload, $encodedSignature]);
    }

    /**
     * @param Key|array<string,Key>|ArrayAccess<string,Key> $keyOrKeys
     */
    public static function decode(string $jwt, Key|array|ArrayAccess $keyOrKeys, ?stdClass &$header = null): stdClass
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new InvalidTokenStructure('Token must have exactly 3 segments.');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $rawHeader = Base64Url::decode($encodedHeader);
        $decodedHeader = Json::decode($rawHeader);
        if (! $decodedHeader instanceof stdClass) {
            $decodedHeader = self::ensureObject($decodedHeader);
        }

        $alg = $decodedHeader->alg ?? null;
        if (! is_string($alg)) {
            throw new InvalidTokenStructure('Token header must contain string "alg".');
        }

        if ($alg === 'none') {
            throw new UnsupportedAlgorithm('The "none" algorithm is not supported.');
        }

        $selectedKey = self::selectKey($decodedHeader, $keyOrKeys);

        $headerAlgorithm = strtoupper($alg);

        if ($selectedKey instanceof Key) {
            $keyAlgorithm = strtoupper($selectedKey->algorithm());
            if ($keyAlgorithm !== $headerAlgorithm) {
                throw new UnsupportedAlgorithm(sprintf('Algorithm mismatch between key (%s) and token (%s).', $keyAlgorithm, $headerAlgorithm));
            }

            $keyMaterial = $selectedKey->material();
            $algorithm = $keyAlgorithm;
        } else {
            $keyMaterial = $selectedKey;
            $algorithm = $headerAlgorithm;
        }

        $payloadJson = Base64Url::decode($encodedPayload);
        $decodedPayload = Json::decode($payloadJson);
        if (! $decodedPayload instanceof stdClass) {
            $decodedPayload = self::ensureObject($decodedPayload);
        }

        $signature = Base64Url::decode($encodedSignature);
        $message = "$encodedHeader.$encodedPayload";

        if (! self::verify($message, $signature, $keyMaterial, $algorithm)) {
            throw new SignatureVerificationFailed('JWT signature verification failed.');
        }

        $header = $decodedHeader;

        return $decodedPayload;
    }

    private static function ensureObject(array|object $value): stdClass
    {
        if (is_object($value)) {
            return $value instanceof stdClass ? $value : self::ensureObject((array) $value);
        }

        return (object) $value;
    }

    /**
     * @param Key|array<string,Key>|ArrayAccess<string,Key> $keyOrKeys
     * @return Key|string
     */
    private static function selectKey(stdClass $header, Key|array|ArrayAccess $keyOrKeys): Key|string
    {
        if ($keyOrKeys instanceof Key) {
            return $keyOrKeys;
        }

        if ($keyOrKeys instanceof ArrayAccess) {
            $keyId = self::extractKid($header);
            if ($keyId !== null && $keyOrKeys->offsetExists($keyId)) {
                /** @var Key $key */
                $key = $keyOrKeys[$keyId];

                return $key;
            }

            throw new KeyNotFound('Unable to locate key for provided token.');
        }

        if (is_array($keyOrKeys)) {
            if ($keyOrKeys === []) {
                throw new KeyNotFound('Key array cannot be empty.');
            }

            if (array_is_list($keyOrKeys)) {
                if (count($keyOrKeys) !== 1) {
                    throw new KeyNotFound('A list of keys requires key identifiers (kid).');
                }

                $candidate = $keyOrKeys[0];
                if (! $candidate instanceof Key) {
                    throw new KeyNotFound('Key entries must be instances of ' . Key::class . '.');
                }

                return $candidate;
            }

            $keyId = self::extractKid($header);
            if ($keyId === null) {
                throw new KeyNotFound('Token header missing kid; unable to select key from keyed array.');
            }

            if (! array_key_exists($keyId, $keyOrKeys)) {
                throw new KeyNotFound(sprintf('No key found for kid "%s".', $keyId));
            }

            $key = $keyOrKeys[$keyId];
            if (! $key instanceof Key) {
                throw new KeyNotFound(sprintf('Key for kid "%s" must be an instance of %s.', $keyId, Key::class));
            }

            return $key;
        }

        throw new KeyNotFound('Unsupported key container supplied.');
    }

    private static function extractKid(stdClass $header): ?string
    {
        $kid = $header->kid ?? null;

        return is_string($kid) ? $kid : null;
    }

    /**
     * @param string|OpenSSLAsymmetricKey|OpenSSLCertificate $key
     */
    private static function sign(string $message, string|OpenSSLAsymmetricKey|OpenSSLCertificate $key, string $algorithm): string
    {
        return match ($algorithm) {
            'HS256' => hash_hmac('sha256', $message, self::toStringKey($key), true),
            'HS384' => hash_hmac('sha384', $message, self::toStringKey($key), true),
            'HS512' => hash_hmac('sha512', $message, self::toStringKey($key), true),
            'RS256' => self::rsaSign($message, $key, OPENSSL_ALGO_SHA256),
            'RS384' => self::rsaSign($message, $key, OPENSSL_ALGO_SHA384),
            'RS512' => self::rsaSign($message, $key, OPENSSL_ALGO_SHA512),
            'ES256' => self::ecdsaSign($message, $key, OPENSSL_ALGO_SHA256, 32),
            'ES384' => self::ecdsaSign($message, $key, OPENSSL_ALGO_SHA384, 48),
            'ES512' => self::ecdsaSign($message, $key, OPENSSL_ALGO_SHA512, 66),
            default => throw new UnsupportedAlgorithm(sprintf('Unsupported signing algorithm "%s".', $algorithm)),
        };
    }

    /**
     * @param string|OpenSSLAsymmetricKey|OpenSSLCertificate $key
     */
    private static function verify(string $message, string $signature, string|OpenSSLAsymmetricKey|OpenSSLCertificate $key, string $algorithm): bool
    {
        return match ($algorithm) {
            'HS256' => hash_equals(hash_hmac('sha256', $message, self::toStringKey($key), true), $signature),
            'HS384' => hash_equals(hash_hmac('sha384', $message, self::toStringKey($key), true), $signature),
            'HS512' => hash_equals(hash_hmac('sha512', $message, self::toStringKey($key), true), $signature),
            'RS256' => self::rsaVerify($message, $signature, $key, OPENSSL_ALGO_SHA256),
            'RS384' => self::rsaVerify($message, $signature, $key, OPENSSL_ALGO_SHA384),
            'RS512' => self::rsaVerify($message, $signature, $key, OPENSSL_ALGO_SHA512),
            'ES256' => self::ecdsaVerify($message, $signature, $key, OPENSSL_ALGO_SHA256, 32),
            'ES384' => self::ecdsaVerify($message, $signature, $key, OPENSSL_ALGO_SHA384, 48),
            'ES512' => self::ecdsaVerify($message, $signature, $key, OPENSSL_ALGO_SHA512, 66),
            default => throw new UnsupportedAlgorithm(sprintf('Unsupported verification algorithm "%s".', $algorithm)),
        };
    }

    private static function rsaSign(string $message, string|OpenSSLAsymmetricKey|OpenSSLCertificate $key, int $algo): string
    {
        if ($key instanceof OpenSSLCertificate) {
            throw new UnsupportedAlgorithm('Cannot sign using a public certificate. Provide a private key instead.');
        }

        $signature = '';
        if (! openssl_sign($message, $signature, $key, $algo)) {
            throw new UnsupportedAlgorithm('Unable to sign message with RSA key.');
        }

        return $signature;
    }

    private static function rsaVerify(string $message, string $signature, string|OpenSSLAsymmetricKey|OpenSSLCertificate $key, int $algo): bool
    {
        return openssl_verify($message, $signature, $key, $algo) === 1;
    }

    private static function ecdsaSign(string $message, string|OpenSSLAsymmetricKey|OpenSSLCertificate $key, int $algo, int $coordinateLength): string
    {
        if ($key instanceof OpenSSLCertificate) {
            throw new UnsupportedAlgorithm('Cannot sign using a public certificate. Provide a private key instead.');
        }

        $der = '';
        if (! openssl_sign($message, $der, $key, $algo)) {
            throw new UnsupportedAlgorithm('Unable to sign message with EC key.');
        }

        return self::derToConcat($der, $coordinateLength);
    }

    private static function ecdsaVerify(string $message, string $signature, string|OpenSSLAsymmetricKey|OpenSSLCertificate $key, int $algo, int $coordinateLength): bool
    {
        if (strlen($signature) !== $coordinateLength * 2) {
            return false;
        }

        try {
            $der = self::concatToDer($signature, $coordinateLength);
        } catch (UnsupportedAlgorithm $exception) {
            return false;
        }

        return openssl_verify($message, $der, $key, $algo) === 1;
    }

    private static function derToConcat(string $der, int $coordinateLength): string
    {
        $offset = 0;

        if (! isset($der[$offset]) || ord($der[$offset]) !== 0x30) {
            throw new UnsupportedAlgorithm('Invalid DER sequence for ECDSA signature.');
        }

        $offset++;
        self::readDerLength($der, $offset);

        if (! isset($der[$offset]) || ord($der[$offset]) !== 0x02) {
            throw new UnsupportedAlgorithm('Invalid DER integer for ECDSA signature.');
        }

        $offset++;
        $rLength = self::readDerLength($der, $offset);
        $r = substr($der, $offset, $rLength);
        $offset += $rLength;

        if (! isset($der[$offset]) || ord($der[$offset]) !== 0x02) {
            throw new UnsupportedAlgorithm('Invalid DER integer for ECDSA signature.');
        }

        $offset++;
        $sLength = self::readDerLength($der, $offset);
        $s = substr($der, $offset, $sLength);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        $r = str_pad($r, $coordinateLength, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $coordinateLength, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    private static function concatToDer(string $signature, int $coordinateLength): string
    {
        if (strlen($signature) !== $coordinateLength * 2) {
            throw new UnsupportedAlgorithm('Invalid ECDSA signature length.');
        }

        $r = substr($signature, 0, $coordinateLength);
        $s = substr($signature, $coordinateLength, $coordinateLength);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        if ($r === '') {
            $r = "\x00";
        }

        if ($s === '') {
            $s = "\x00";
        }

        if ((ord($r[0]) & 0x80) !== 0) {
            $r = "\x00" . $r;
        }

        if ((ord($s[0]) & 0x80) !== 0) {
            $s = "\x00" . $s;
        }

        $der = chr(0x02) . self::encodeDerLength(strlen($r)) . $r;
        $der .= chr(0x02) . self::encodeDerLength(strlen($s)) . $s;

        return chr(0x30) . self::encodeDerLength(strlen($der)) . $der;
    }

    private static function readDerLength(string $der, int &$offset): int
    {
        if (! isset($der[$offset])) {
            throw new UnsupportedAlgorithm('Invalid DER length encoding.');
        }

        $length = ord($der[$offset]);
        $offset++;

        if (($length & 0x80) === 0) {
            return $length;
        }

        $numBytes = $length & 0x7F;
        if ($numBytes === 0 || $numBytes > 4) {
            throw new UnsupportedAlgorithm('Invalid DER length encoding.');
        }

        if ($offset + $numBytes > strlen($der)) {
            throw new UnsupportedAlgorithm('DER length exceeds available bytes.');
        }

        $length = 0;
        for ($i = 0; $i < $numBytes; $i++, $offset++) {
            $length = ($length << 8) | ord($der[$offset]);
        }

        return $length;
    }

    private static function encodeDerLength(int $length): string
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

    /**
     * @param string|OpenSSLAsymmetricKey|OpenSSLCertificate $key
     */
    private static function toStringKey(string|OpenSSLAsymmetricKey|OpenSSLCertificate $key): string
    {
        if (! is_string($key)) {
            throw new UnsupportedAlgorithm('HMAC algorithms require a string key.');
        }

        return $key;
    }
}
