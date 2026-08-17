<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Où les codes de secours d'un compte sont rangés.
 *
 * Le paquet ne range rien lui-même : il donne des empreintes, il en réclame, il en fait
 * retirer. Ce qu'il confie n'ouvre rien — une empreinte ne se remonte pas en code.
 *
 * Une implémentation qui rendrait les codes en clair, ou qui les garderait après usage, rendrait
 * inutile tout ce qui précède.
 */
interface BackupCodeStore
{
    /**
     * Remplace d'un bloc les codes du compte : poser une nouvelle série périme la précédente.
     *
     * @param list<string> $hashes les empreintes des nouveaux codes, jamais les codes
     */
    public function replaceAll(string $userIdentifier, array $hashes): void;

    /**
     * Les empreintes encore utilisables de ce compte.
     *
     * @return list<string>
     */
    public function hashesFor(string $userIdentifier): array;

    /**
     * Retire une empreinte, parce que le code correspondant vient de servir.
     *
     * Un code de secours ne sert qu'une fois : le laisser en place reviendrait à distribuer un
     * mot de passe permanent sur une feuille imprimée.
     */
    public function forget(string $userIdentifier, string $hash): void;
}
