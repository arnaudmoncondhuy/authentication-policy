<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Firewall;
use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Le pare-feu courant, lu dans la carte que le SecurityBundle tient.
 *
 * La carte est facultative à l'injection : une application sans SecurityBundle installe le
 * paquet sans erreur, et n'en reçoit alors aucune garantie — ce qui est exact, puisqu'elle
 * n'authentifie personne.
 */
final readonly class MappedFirewall implements Firewall
{
    public function __construct(
        private RequestStack $requests,
        private ?FirewallMap $firewalls = null,
    ) {
    }

    public function name(): ?string
    {
        $request = $this->requests->getMainRequest();

        return null === $request || null === $this->firewalls
            ? null
            : $this->firewalls->getFirewallConfig($request)?->getName();
    }
}
