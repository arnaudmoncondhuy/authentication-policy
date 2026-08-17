<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\CurrentDecisions;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ExitDoor;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\MappedFirewall;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\SessionLifetimeListener;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\SystemClock;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\Visitor;
use ArnaudMoncondhuy\AuthenticationPolicy\Firewall;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\RequestStack;
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

        // Sous quel pare-feu la requête est traitée. La carte est un service privé du
        // SecurityBundle : `nullOnInvalid` couvre les montages où elle n'existe pas, et le
        // paquet ne couvre alors rien.
        ->set(MappedFirewall::class)
            ->args([
                service(RequestStack::class),
                service('security.firewall.map')->nullOnInvalid(),
            ])
        ->alias(Firewall::class, MappedFirewall::class)

        // Par où repartir quand on s'arrête au second facteur. Le pare-feu peut n'avoir pas de
        // sortie déclarée : le bouton disparaît alors, au lieu de mener nulle part.
        ->set(ExitDoor::class)
            ->args([service('security.logout_url_generator')->nullOnInvalid()])

        // Qui règle sa sécurité, et le pare-feu dont il relève. Les deux questions vont
        // ensemble : les séparer laisserait un compte de machine régler des moyens qu'il ne
        // posera jamais. Déclaré ici et non avec les écrans — le pont en a besoin dans une
        // application qui ne rend aucune page.
        ->set(Visitor::class)
            ->args([
                service(TokenStorageInterface::class),
                service(Perimeter::class),
                service(Firewall::class)->nullOnInvalid(),
            ])

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
                service(Perimeter::class),
                service(Firewall::class),
            ])
            ->tag('kernel.event_listener', ['event' => LoginSuccessEvent::class, 'method' => 'onLogin'])
            ->tag('kernel.event_listener', ['event' => 'kernel.request', 'method' => 'onRequest', 'priority' => 4])
    ;
};
