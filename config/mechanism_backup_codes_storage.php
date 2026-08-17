<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\DbalBackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Tables;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le rangement du paquet, importé seulement quand l'application n'en nomme pas d'autre.
 *
 * Séparé du mécanisme : décrit inconditionnellement, il réclamerait une base de données à une
 * application qui range pourtant ailleurs.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(DbalBackupCodes::class)
            ->args([service(Tables::class)])
            ->tag('authentication_policy.forgettable')

        ->alias(Parameter::STORE.'.backup_codes', DbalBackupCodes::class)
    ;
};
