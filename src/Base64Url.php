<?php

declare(strict_types=1);

namespace Nyra\Jwt;

final class Base64Url
{
    public static function encode(string $data): string
    {
        $encoded = base64_encode($data);
        $encoded = rtrim($encoded, '=');
        $encoded = strtr($encoded, '+/', '-_');

        return $encoded;
    }

    public static function decode(string $data): string
    {
        $padding = 4 - (strlen($data) % 4);
        if ($padding !== 4) {
            $data .= str_repeat('=', $padding);
        }

        $data = strtr($data, '-_', '+/');

        $decoded = base64_decode($data, true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid base64url string provided.');
        }

        return $decoded;
    }
}
