<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey;

/**
 * Où les clés d'un compte sont rangées.
 *
 * Le paquet ne connaît pas la table des comptes : tout est indexé par l'identité que le jeton
 * de sécurité porte, et l'identité opaque que la norme réclame est fabriquée ici plutôt
 * qu'empruntée à une clé primaire dont le paquet ignore tout.
 */
interface SecurityKeys
{
    /** @return list<StoredKey> dans l'ordre où elles ont été posées */
    public function findAllOf(string $userIdentifier): array;

    /** @param string $rawCredentialId les octets bruts, tels que le navigateur les rend */
    public function findOneByCredentialId(string $rawCredentialId): ?StoredKey;

    public function findOneOf(string $userIdentifier, string $credentialId): ?StoredKey;

    /**
     * L'identité opaque de ce compte auprès des appareils, stable d'une clé à l'autre.
     *
     * Elle doit être la même pour toutes les clés d'un compte : deux identités feraient
     * apparaître deux comptes distincts dans la liste d'un téléphone.
     *
     * @return non-empty-string
     */
    public function handleOf(string $userIdentifier): string;

    public function save(StoredKey $key): void;

    public function remove(StoredKey $key): void;

    /** @param non-empty-string $record l'enregistrement remis à jour après une signature */
    public function noteUsage(StoredKey $key, string $record, int $at): void;
}
