<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\ConfiguredRolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\PolicyFactory;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Importé partout : la politique et sa résolution ne dépendent ni d'un pare-feu, ni d'une
 * requête. Une commande, un test ou une tâche planifiée les atteignent de la même façon.
 *
 * Le stockage des préférences est facultatif à l'injection — `nullOnInvalid` — et non parce
 * qu'il serait optionnel : c'est RefuseDelegationWithoutStorePass qui refuse de compiler quand
 * la politique délègue sans que rien ne soit branché. Le nul ici est le cas où l'on ne délègue
 * rien, et où réclamer un stockage rendrait le paquet ininstallable.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(Perimeter::class)
            ->args([param(Parameter::FIREWALLS)])

        ->set(Policy::class)
            ->factory([PolicyFactory::class, 'fromArray'])
            ->args([param(Parameter::RULES)])

        // Le rangement le plus simple des politiques de rôle : celui que la configuration
        // écrit. Une application qui les lit ailleurs déclare son propre service, chargé après
        // celui-ci et qui prend donc sa place.
        ->set(ConfiguredRolePolicies::class)
            ->args([param(Parameter::ROLE_POLICIES)])

        ->alias(RolePolicies::class, ConfiguredRolePolicies::class)

        ->set(PolicyResolver::class)
            ->args([
                service(Policy::class),
                service(RolePolicies::class),
                service(UserPreferences::class)->nullOnInvalid(),
            ])
    ;
};
