<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvent;

/**
 * Note l'instant où l'étape de connexion a été franchie.
 *
 * Le second facteur présenté à l'entrée compte comme une preuve : sans cela, quelqu'un qui
 * vient de taper son code se le verrait redemander à la première action qui l'exige, dans la
 * minute.
 *
 * Sur l'achèvement de l'étape, et non sur le succès de la connexion : le mot de passe seul ne
 * prouve rien de plus que lui-même, et le marquer ferait passer pour récente une identité que
 * personne n'a confirmée.
 */
final readonly class ProofAtLogin
{
    public function __construct(private ProvenMoment $moment)
    {
    }

    public function __invoke(TwoFactorAuthenticationEvent $event): void
    {
        $this->moment->record();
    }
}
