<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp;

/**
 * Où le secret partagé d'un compte est rangé.
 *
 * Un secret posé et jamais confirmé ne vaut rien : rien ne prouverait alors que l'application
 * d'authentification ait été correctement réglée, et le compte se croirait protégé par un code
 * que personne ne sait produire. Les deux états se lisent donc séparément.
 */
interface TotpSecrets
{
    /**
     * Le secret posé, confirmé ou non — ce qu'il faut pour fabriquer le QR code.
     *
     * @return non-empty-string|null un secret vide n'est pas un secret : c'est un compte sans
     *                               rien, et le rendre comme tel évite de le confondre
     */
    public function secretOf(string $userIdentifier): ?string;

    /**
     * Le secret dont un premier code juste a prouvé qu'il fonctionne, et lui seul.
     *
     * @return non-empty-string|null
     */
    public function confirmedSecretOf(string $userIdentifier): ?string;

    /**
     * Range un secret neuf, non confirmé, en remplaçant celui qui s'y trouvait.
     *
     * Remplacer plutôt qu'ajouter : deux secrets pour un compte laisseraient entrer avec celui
     * qu'on croyait avoir abandonné.
     *
     * @param non-empty-string $secret
     */
    public function remember(string $userIdentifier, string $secret): void;

    /** @param int $at horodatage Unix de la confirmation */
    public function confirm(string $userIdentifier, int $at): void;

    public function forget(string $userIdentifier): void;
}
