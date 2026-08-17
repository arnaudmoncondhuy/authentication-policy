<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\FactorProof;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\InsufficientProofListener;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ProofAtLogin;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ProvenMoment;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ReturnPath;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\Visitor;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;
use Psr\Clock\ClockInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvents;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le pont vers le paquet d'autorisation.
 *
 * Importé seulement quand ce paquet est installé ET qu'un mécanisme est allumé : déclaré sans
 * mécanisme, ce juge ne pourrait répondre que non, et une action protégée deviendrait
 * inatteignable par tout le monde sans que rien ne le dise. Mieux vaut alors qu'il n'existe
 * pas — le paquet voisin refuse de compiler, et le message nomme la cause.
 *
 * Aucune dépendance obligatoire n'en découle dans un sens ni dans l'autre : `authorization`
 * ignore ce paquet, celui-ci ne le cite qu'ici et dans deux adaptateurs.
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services
        ->set(ProvenMoment::class)
            ->args([service(RequestStack::class), service(ClockInterface::class)])

        ->set(FactorProof::class)
            ->args([
                service(Factors::class),
                service(Visitor::class),
                service(ProvenMoment::class),
                param(Parameter::PROOF_FRESHNESS),
            ])

        // C'est l'alias que le paquet voisin interroge, et son absence est ce qui arrête sa
        // compilation quand un droit exige une preuve.
        ->alias(ProofOfIdentity::class, FactorProof::class)

        ->set(ReturnPath::class)
            ->args([service(RequestStack::class), param(Parameter::ENROLLMENT_PATH)])
    ;

    // Le second facteur présenté à l'entrée compte comme une preuve. Sans l'étape de
    // connexion, il n'y a rien à noter là : seul l'écran de redemande marque alors l'instant.
    if (class_exists(TwoFactorAuthenticationEvents::class)) {
        $services
            ->set(ProofAtLogin::class)
                ->args([service(ProvenMoment::class)])
                ->tag('kernel.event_listener', ['event' => TwoFactorAuthenticationEvents::COMPLETE])
        ;
    }

    $services
        ->set(InsufficientProofListener::class)
            ->args([
                service(ProofOfIdentity::class),
                service(ReturnPath::class),
                service(UrlGeneratorInterface::class),
                param(Parameter::ENROLLMENT_PATH),
            ])
            ->tag('kernel.event_listener', ['event' => 'kernel.exception'])
    ;
};
