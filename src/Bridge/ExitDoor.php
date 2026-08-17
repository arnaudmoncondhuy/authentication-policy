<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use Symfony\Component\Security\Http\Logout\LogoutUrlGenerator;

/**
 * Par où repartir quand on s'arrête au second facteur.
 *
 * Sans cette porte, qui n'a pas son code sous la main n'a plus rien : il n'est pas encore
 * entré, donc aucune page ne lui répond, et il n'est pas non plus sorti, donc la session
 * l'attend. Il ne lui reste qu'à patienter jusqu'à l'expiration.
 *
 * Le chemin appartient à l'application — c'est son pare-feu qui l'intercepte. Le paquet le
 * demande et se tait s'il n'existe pas, plutôt que d'imposer une route de son cru.
 */
final readonly class ExitDoor
{
    public function __construct(private ?LogoutUrlGenerator $logout = null)
    {
    }

    public function path(): ?string
    {
        try {
            return $this->logout?->getLogoutPath();
        } catch (\Throwable) {
            // Un pare-feu sans sortie déclarée lève. Rendre nul retire le bouton ; lever
            // remplacerait l'écran du second facteur par une page d'erreur.
            return null;
        }
    }
}
