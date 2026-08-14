<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\PolicyFactory;
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
 * Les deux stockages sont facultatifs à l'injection — `nullOnInvalid` — et non parce qu'ils
 * seraient optionnels : c'est RefuseDelegationWithoutStorePass qui refuse de compiler quand la
 * politique délègue sans que rien ne soit branché. Le nul ici est le cas où l'on ne délègue
 * rien, et où réclamer un stockage rendrait le paquet ininstallable.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(Policy::class)
            ->factory([PolicyFactory::class, 'fromArray'])
            ->args([param(Parameter::RULES)])

        ->set(PolicyResolver::class)
            ->args([
                service(Policy::class),
                service(RolePolicies::class)->nullOnInvalid(),
                service(UserPreferences::class)->nullOnInvalid(),
            ])
    ;
};
