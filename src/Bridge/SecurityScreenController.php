<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;

/**
 * L'écran « Ma sécurité » : ce qui protège le compte, et ce qui lui manque.
 *
 * Aucun mécanisme n'y est nommé : l'écran affiche ce que les moyens installés déclarent.
 *
 * Il ne montre ni ne règle la durée des sessions. Elle se décide en configuration, comme la
 * force du chiffrement ou la longueur d'un mot de passe : ce n'est pas une préférence, et
 * l'afficher inviterait à en discuter.
 */
#[DuringEnrollment('C\'est la page qui mène aux moyens : le verrou doit la laisser passer.')]
final readonly class SecurityScreenController
{
    public function __construct(
        private Factors $factors,
        private Visitor $visitor,
        private Environment $twig,
        private string $template,
        private ?string $layout,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $user = $this->visitor->identifier();
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
