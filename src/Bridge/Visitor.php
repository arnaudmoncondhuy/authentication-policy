<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Firewall;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * Qui règle sa sécurité, et a-t-il le droit d'être là.
 *
 * Les deux questions vont ensemble et se posent au même endroit : un écran qui vérifierait
 * l'une sans l'autre laisserait un compte de machine régler des moyens qu'il ne posera jamais,
 * ou rendrait une page vide à qui n'est pas connecté.
 */
final readonly class Visitor
{
    public function __construct(
        private TokenStorageInterface $tokens,
        private Perimeter $perimeter,
        private ?Firewall $firewall,
    ) {
    }

    /**
     * @throws AccessDeniedException hors du périmètre, ou sans compte connecté
     */
    public function identifier(): string
    {
        // Sans carte des pare-feux, rien ne situe la requête : refuser est le seul comportement
        // qui ne suppose pas ce qu'on ne sait pas.
        if (null === $this->firewall || !$this->perimeter->covers($this->firewall->name())) {
            throw new AccessDeniedException('Ces écrans ne répondent qu\'aux pare-feux confiés à ce paquet.');
        }

        $user = $this->tokens->getToken()?->getUserIdentifier();

        if (null === $user || '' === $user) {
            throw new AccessDeniedException('La sécurité d\'un compte se règle une fois connecté.');
        }

        return $user;
    }

    /** @return list<string> */
    public function roles(): array
    {
        return array_values($this->tokens->getToken()?->getRoleNames() ?? []);
    }
}
