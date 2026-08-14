<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\CurrentDecisions;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\SessionLifetimeListener;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\SystemClock;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Importé seulement quand SecurityBundle est enregistré : sans lui, le stockage de jeton n'est
 * pas un service, et ce fichier rendrait le paquet ininstallable dans une application sans
 * pare-feu.
 *
 * L'horloge est déclarée ici et pas ailleurs : le paquet apporte la sienne pour ne dépendre
 * d'aucun composant qu'une application n'aurait pas installé. Une application qui a déjà une
 * horloge remplace l'alias.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(SystemClock::class)
        ->alias(ClockInterface::class, SystemClock::class)

        // Ce qu'un écran de profil injecte : la politique appliquée à qui est connecté.
        ->set(CurrentDecisions::class)
            ->args([service(PolicyResolver::class), service(TokenStorageInterface::class)])
            ->public()

        // Les durées se résolvent à la connexion et se relisent à chaque requête. La priorité 4
        // place le contrôle après le pare-feu, qui démarre la session à la priorité 8 : plus
        // haut, il n'y aurait encore ni session ni jeton à lire.
        ->set(SessionLifetimeListener::class)
            ->args([
                service(PolicyResolver::class),
                service(TokenStorageInterface::class),
                service(ClockInterface::class),
            ])
            ->tag('kernel.event_listener', ['event' => LoginSuccessEvent::class, 'method' => 'onLogin'])
            ->tag('kernel.event_listener', ['event' => 'kernel.request', 'method' => 'onRequest', 'priority' => 4])
    ;
};
