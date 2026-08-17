<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Ce que la configuration pose sur les rôles.
 *
 * Le rangement le plus simple qui tienne le contrat : les valeurs sont écrites dans le fichier
 * du paquet, relues telles quelles, et validées au moment de compiler — un réglage inconnu ou
 * une durée écrite en chaîne arrêtent la construction du conteneur, avec le nom du rôle fautif.
 *
 * Une application qui lit ses politiques ailleurs — une table d'administration, un annuaire —
 * implémente {@see RolePolicies} et nomme son service en configuration.
 */
final readonly class ConfiguredRolePolicies implements RolePolicies
{
    /** @param array<string, array<string, bool|int>> $policies indexé par nom de rôle */
    public function __construct(private array $policies)
    {
    }

    public function valuesFor(string $role): array
    {
        return $this->policies[$role] ?? [];
    }
}
