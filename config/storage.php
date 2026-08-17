<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Oblivion;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Tables;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/*
 * Le rangement du paquet, importé quand Doctrine est là.
 *
 * Sans lui, chaque mécanisme attend que l'application nomme le sien ; les passes de compilation
 * refusent alors une configuration qui allumerait un mécanisme sans rien pour le ranger.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(Tables::class)
            ->args([
                service(Parameter::CONNECTION),
                param(Parameter::TABLE_PREFIX),
                param(Parameter::AUTO_SETUP),
            ])

        // Public : c'est un cas d'usage de l'application qui l'appelle, au moment de supprimer
        // un compte. Aucune clé étrangère ne peut faire ce travail à sa place.
        ->set(Oblivion::class)
            ->args([tagged_iterator('authentication_policy.forgettable')])
            ->public()
    ;
};
