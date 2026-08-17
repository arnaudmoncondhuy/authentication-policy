<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodeStore;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le mécanisme des codes de secours, importé seulement quand l'application les allume.
 *
 * La marque est posée ici et nulle part ailleurs : rien ne marque un moyen automatiquement, et
 * une classe venue d'ailleurs se ferait sinon compter sans que le paquet réponde de sa
 * solidité.
 *
 * Le rangement est atteint par un alias : le point de montage le fait pointer vers celui de
 * l'application quand elle en nomme un, sans avoir à connaître une seule classe d'ici.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(BackupCodes::class)
            ->args([
                service(Parameter::STORE.'.backup_codes'),
                service(Factors::class),
                param(Parameter::MECHANISM.'.backup_codes.how_many'),
                param(Parameter::MECHANISM.'.backup_codes.length'),
            ])
            ->tag('authentication_policy.factor')
            ->public()

        ->alias(BackupCodeStore::class, Parameter::STORE.'.backup_codes')
    ;
};
