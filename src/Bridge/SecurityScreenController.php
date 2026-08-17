<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Twig\Environment;

/**
 * L'écran « Ma sécurité » : tous les moyens du compte au même endroit.
 *
 * Un écran par mécanisme obligerait chacun à en écrire un de plus, et la personne à faire le
 * tour de son profil pour savoir où elle en est. Ici, ce qui est posé se lit d'un coup d'œil,
 * ce qui manque se propose à la suite, et chaque ligne mène là où on la gère.
 *
 * Aucun mécanisme n'est nommé : l'écran affiche ce que les moyens installés déclarent.
 */
final readonly class SecurityScreenController
{
    public function __construct(
        private Factors $factors,
        private TokenStorageInterface $tokens,
        private Environment $twig,
        private string $template,
        private ?string $layout,
    ) {
    }

    public function __invoke(): Response
    {
        $user = $this->tokens->getToken()?->getUserIdentifier();

        if (null === $user || '' === $user) {
            throw new AccessDeniedException('La sécurité d\'un compte se règle une fois connecté.');
        }

        $inventory = $this->factors->inventoryFor($user);

        return new Response($this->twig->render($this->template, [
            'layout' => $this->layout,
            'poses' => array_values(array_filter($inventory, static fn (array $factor): bool => $factor['count'] > 0)),
            'a_poser' => array_values(array_filter($inventory, static fn (array $factor): bool => 0 === $factor['count'])),
            'total' => $this->factors->countFor($user),
            'recours' => $this->factors->hasRecoveryFor($user),
        ]));
    }
}
