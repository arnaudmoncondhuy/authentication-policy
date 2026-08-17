<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\BackupCodesController;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\SecurityScreenController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * La route de l'écran des codes de secours.
 *
 * Importée par l'application, jamais posée d'office : c'est elle qui décide sous quel chemin
 * l'écran vit, et le chemin est ce que les gens retiennent.
 */
return static function (RoutingConfigurator $routes): void {
    $routes->add('authentication_policy_security', '/securite')
        ->controller(SecurityScreenController::class)
        ->methods(['GET'])
    ;

    $routes->add('authentication_policy_backup_codes', '/codes-de-secours')
        ->controller(BackupCodesController::class)
        ->methods(['GET', 'POST'])
    ;
};
