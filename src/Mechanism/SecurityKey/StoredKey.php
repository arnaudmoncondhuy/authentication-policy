<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey;

/**
 * Une clé posée, telle que le rangement la rend.
 *
 * L'identifiant voyage en base64 : la norme en fait une suite d'octets quelconques, qui ne
 * tiendrait pas dans une colonne de texte ni dans une adresse.
 */
final readonly class StoredKey
{
    /**
     * @param non-empty-string $credentialId en base64
     * @param non-empty-string $record       l'enregistrement sérialisé par {@see Record}
     */
    public function __construct(
        public string $credentialId,
        public string $userIdentifier,
        public string $userHandle,
        public string $label,
        public Kind $kind,
        public string $record,
        public int $createdAt,
        public ?int $lastUsedAt = null,
    ) {
    }

    /** Les octets bruts que la norme attend dans un descripteur. */
    public function rawId(): string
    {
        return (string) base64_decode($this->credentialId, true);
    }

    /** @return list<string> */
    public function transports(): array
    {
        return Record::transportsIn($this->record);
    }
}
