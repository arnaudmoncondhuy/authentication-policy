<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\DoctorCommand;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\PolicyCommand;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Enrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Importé partout où symfony/console est installé, pare-feu ou non : afficher la politique ne
 * demande ni requête ni compte connecté.
 *
 * Le docteur reçoit les stockages en `nullOnInvalid` parce que leur absence est justement ce
 * qu'il rapporte. Les recevoir autrement le rendrait impossible à construire dans l'application
 * qui en a le plus besoin.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(PolicyCommand::class)
            ->args([
                service(Policy::class),
                service(RolePolicies::class)->nullOnInvalid(),
            ])
            ->tag('console.command')

        ->set(DoctorCommand::class)
            ->args([
                service(Policy::class),
                param(Parameter::FINDINGS),
                param(Parameter::ENROLLMENT_PATH),
                service(RolePolicies::class)->nullOnInvalid(),
                service(UserPreferences::class)->nullOnInvalid(),
                service(Enrollment::class)->nullOnInvalid(),
            ])
            ->tag('console.command')
    ;
};
