<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\Factor;

/**
 * Un moyen écrit par l'application, comme le serait un code à six chiffres déjà installé.
 *
 * Il ne porte aucune marque : c'est au paquet de la poser, faute de quoi il ne compterait que
 * ses propres mécanismes.
 */
final class ApplicationFactor implements Factor
{
    public function name(): string
    {
        return 'quelque_chose_de_l_application';
    }

    public function countFor(string $userIdentifier): int
    {
        return 'arnaud' === $userIdentifier ? 1 : 0;
    }
}
