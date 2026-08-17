<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/**
 * Refuse de compiler le conteneur si un mécanisme est allumé sans que rien ne le demande à la
 * connexion.
 *
 * Le paquet fabrique les moyens, les range, les compte et les affiche. Il ne pose pas l'étape
 * de second facteur : c'est le pare-feu de l'application qui la pose, et lui seul sait où.
 *
 * Sans cette étape, tout paraît en place — l'écran propose de poser une clé, la clé se pose,
 * elle se compte, le verrou s'ouvre — et **personne ne la demande jamais**. Le compte se croit
 * protégé par un moyen qui ne sert à rien. C'est la faute la plus coûteuse que ce paquet
 * puisse laisser passer, parce qu'elle se solde par une fausse confiance.
 */
final readonly class RefuseMechanismWithoutTwoFactorListenerPass implements CompilerPassInterface
{
    /** Ce que scheb/2fa-bundle nomme quand un pare-feu déclare son étape de second facteur. */
    private const string AUTHENTICATOR = 'security.authenticator.two_factor.';

    public function process(ContainerBuilder $container): void
    {
        if (!$this->anyMechanismEnabled($container) || !$container->hasParameter(Parameter::FIREWALLS)) {
            return;
        }

        /** @var list<string> $firewalls */
        $firewalls = $container->getParameter(Parameter::FIREWALLS);
        $missing = [];

        foreach ($firewalls as $firewall) {
            if (!$container->has(self::AUTHENTICATOR.$firewall)) {
                $missing[] = $firewall;
            }
        }

        if ([] === $missing) {
            return;
        }

        throw new LogicException(\sprintf("Des moyens d'authentification sont allumés, mais ces pare-feux ne demandent jamais de second facteur :\n  - %s\nLes moyens se poseraient et se compteraient sans que personne ne les réclame à la connexion.\nÀ écrire dans la configuration de sécurité, sous chacun d'eux :\n\n            two_factor:\n                auth_form_path: authentication_policy_login\n                check_path: authentication_policy_login_check\n", implode("\n  - ", $missing)));
    }

    private function anyMechanismEnabled(ContainerBuilder $container): bool
    {
        if (!$container->hasParameter(Parameter::MECHANISMS)) {
            return false;
        }

        /** @var array<string, array{enabled: bool}> $mechanisms */
        $mechanisms = $container->getParameter(Parameter::MECHANISMS);

        foreach ($mechanisms as $mechanism) {
            if ($mechanism['enabled']) {
                return true;
            }
        }

        return false;
    }
}
