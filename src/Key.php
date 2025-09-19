<?php

declare(strict_types=1);

namespace Nyra\Jwt;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

final class Key
{
    /**
     * @param string|OpenSSLAsymmetricKey|OpenSSLCertificate $material
     */
    public function __construct(
        private readonly string|OpenSSLAsymmetricKey|OpenSSLCertificate $material,
        private readonly string $algorithm,
        private readonly ?string $keyId = null
    ) {
    }

    /**
     * @return string|OpenSSLAsymmetricKey|OpenSSLCertificate
     */
    public function material(): string|OpenSSLAsymmetricKey|OpenSSLCertificate
    {
        return $this->material;
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    public function keyId(): ?string
    {
        return $this->keyId;
    }
}
