<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\EnrollmentLockListener;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Enrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Importé seulement quand la politique peut exiger un second facteur. Autrement, le verrou
 * réclamerait le contrat qui dit qui s'est enrôlé, alors qu'aucune application n'aurait de
 * raison de l'écrire.
 *
 * Ni `nullOnInvalid` sur le contrat, ni valeur par défaut sur le chemin : les deux manquants
 * arrêtent la compilation par RefuseLockWithoutExitPass, avec la phrase qui dit quoi faire.
 * Une valeur de repli fermerait l'application sur une redirection vers une page qui n'existe
 * pas.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(EnrollmentLockListener::class)
            ->args([
                service(PolicyResolver::class),
                service(TokenStorageInterface::class),
                service(Enrollment::class),
                param(Parameter::ENROLLMENT_PATH),
            ])
            ->tag('kernel.event_listener', ['event' => 'kernel.controller'])
    ;
};
