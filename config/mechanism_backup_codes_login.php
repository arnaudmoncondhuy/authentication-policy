<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ExitDoor;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodesAtLogin;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Twig\Environment;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * L'étape de connexion du mécanisme, importée quand l'application sait poser un second facteur.
 *
 * L'alias de la marque est le nom du mécanisme : c'est sous ce nom que l'écran de vérification
 * propose de passer d'un moyen à l'autre.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(BackupCodesAtLogin::class)
            ->args([
                service(BackupCodes::class),
                service(Perimeter::class),
                service(ExitDoor::class),
                service(Environment::class),
                param(Parameter::TEMPLATE.'.login_backup_codes'),
                param(Parameter::TEMPLATE.'.login_layout'),
            ])
            ->tag('scheb_two_factor.provider', ['alias' => 'backup_codes'])
    ;
};
