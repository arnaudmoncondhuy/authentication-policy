<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Storage;

/**
 * Efface d'un compte tout ce que le paquet range, sans nommer un seul mécanisme.
 *
 * C'est ce qu'un cas d'usage de suppression de compte appelle. Sans lui, supprimer quelqu'un
 * laisse son secret, ses clés et ses codes en base : personne ne s'en aperçoit tant que
 * l'adresse n'est pas réutilisée, et le jour où elle l'est, le nouveau compte hérite des moyens
 * d'authentification de l'ancien.
 */
final readonly class Oblivion
{
    /** @param iterable<Forgettable> $stores tous les rangements installés, mécanismes compris */
    public function __construct(private iterable $stores)
    {
    }

    public function forgetEverythingOf(string $userIdentifier): void
    {
        foreach ($this->stores as $store) {
            $store->forgetEverythingOf($userIdentifier);
        }
    }
}
