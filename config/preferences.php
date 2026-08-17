<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Storage\DbalUserPreferences;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Tables;
use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le rangement des choix personnels, importé quand ils sont allumés et que Doctrine est là.
 *
 * Éteints, aucun alias n'est posé : la politique qui déléguerait quand même à la personne
 * n'aurait nulle part où ranger ce choix, et RefuseDelegationWithoutStorePass le dit.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(DbalUserPreferences::class)
            ->args([service(Tables::class)])
            ->tag('authentication_policy.forgettable')

        ->alias(UserPreferences::class, DbalUserPreferences::class)
    ;
};
