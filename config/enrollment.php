<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\EnrollmentLockListener;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Firewall;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Importé seulement quand la politique peut exiger un second facteur. Autrement, le verrou
 * surveillerait un enrôlement que rien n'exige.
 *
 * Pas de valeur de repli sur le chemin : son absence arrête la compilation par
 * RefuseLockWithoutExitPass, avec la phrase qui dit quoi faire. Un repli fermerait
 * l'application sur une redirection vers une page qui n'existe pas.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(EnrollmentLockListener::class)
            ->args([
                service(PolicyResolver::class),
                service(TokenStorageInterface::class),
                service(Factors::class),
                service(Perimeter::class),
                service(Firewall::class),
                param(Parameter::ENROLLMENT_PATH),
            ])
            ->tag('kernel.event_listener', ['event' => 'kernel.controller'])
    ;
};
