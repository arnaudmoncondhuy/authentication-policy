<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Refuse de compiler le conteneur si les écrans qui retirent un moyen ne sont protégés par rien.
 *
 * Les écrans du paquet acceptent un jeton et se taisent quand rien ne sait le vérifier — ce qui
 * est le bon comportement pour un paquet installable partout, et le mauvais dès qu'un écran
 * **retire** un moyen d'authentification.
 *
 * Sans cette vérification, une page visitée ailleurs peut faire retirer une clé, périmer une
 * série de codes ou effacer un secret, sans que la personne ait rien demandé. L'absence ne
 * produit aucune erreur : c'est le silence qui la rend dangereuse.
 */
final readonly class RefuseUnprotectedRemovalPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$this->anyMechanismEnabled($container)) {
            return;
        }

        // Les écrans ne sont montés qu'avec Twig ; sans eux, rien ne retire quoi que ce soit.
        /** @var array<string, class-string> $bundles */
        $bundles = $container->getParameter('kernel.bundles');

        if (!isset($bundles['TwigBundle']) || $container->has(CsrfTokenManagerInterface::class)) {
            return;
        }

        throw new LogicException(\sprintf("Des moyens d'authentification sont allumés, et leurs écrans peuvent en retirer sans qu'aucun jeton ne les protège : aucun service n'implémente %s.\nUne page visitée ailleurs pourrait faire retirer une clé ou périmer une série de codes sans que personne l'ait demandé.\nInstaller « symfony/security-csrf » et l'activer, ou éteindre les mécanismes.", CsrfTokenManagerInterface::class));
    }

    private function anyMechanismEnabled(ContainerBuilder $container): bool
    {
        if (!$container->hasParameter(Parameter::MECHANISMS)) {
            return false;
        }

        /** @var array<string, array{enabled: bool}> $mechanisms */
        $mechanisms = $container->getParameter(Parameter::MECHANISMS);

        foreach ($mechanisms as $mechanism) {
            if ($mechanism['enabled']) {
                return true;
            }
        }

        return false;
    }
}
