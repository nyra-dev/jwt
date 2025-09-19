<?php

declare(strict_types=1);

namespace Nyra\Jwt;

use JsonException;

final class Json
{
    /**
     * @param array<mixed>|object $data
     */
    public static function encode(array|object $data): string
    {
        try {
            return json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new \InvalidArgumentException('Unable to encode value to JSON: ' . $exception->getMessage(), 0, $exception);
        }
    }

    /**
     * @return array<mixed>|object
     */
    public static function decode(string $json): array|object
    {
        try {
            $decoded = json_decode($json, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new \InvalidArgumentException('Unable to decode JSON: ' . $exception->getMessage(), 0, $exception);
        }

        return $decoded;
    }
}
