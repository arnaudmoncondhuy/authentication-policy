<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use ArnaudMoncondhuy\AuthenticationPolicy\Factor;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/**
 * Refuse de compiler le conteneur si un moyen d'authentification vient d'ailleurs.
 *
 * Le paquet compte les moyens posés sur un compte, refuse de retirer le dernier, et ferme le
 * verrou sur qui n'en a aucun. Ces trois promesses portent sur ce qu'il a écrit lui-même. Un
 * moyen venu d'ailleurs se ferait compter sans que rien ne réponde de sa solidité : le paquet
 * garantirait un compte protégé par un mécanisme dont il ne sait rien.
 *
 * Un mécanisme s'allume donc en configuration, et ne s'apporte pas.
 */
final readonly class RefuseForeignFactorPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        // Le dossier du contrat, et non « /vendor/ » : ce dernier accepterait le moyen d'un
        // autre paquet, et refuserait les nôtres dès que celui-ci est monté en dépôt de chemin.
        $file = (new \ReflectionClass(Factor::class))->getFileName();

        if (false === $file) {
            return;
        }

        $home = strtr(\dirname($file), '\\', '/').'/';
        $foreign = [];

        foreach ($container->getDefinitions() as $id => $definition) {
            $reflection = $container->getReflectionClass($definition->getClass() ?? $id, false);

            if (!$reflection instanceof \ReflectionClass
                || $reflection->isInterface()
                || !$reflection->implementsInterface(Factor::class)) {
                continue;
            }

            $source = $reflection->getFileName();

            if (false === $source || !str_starts_with(strtr($source, '\\', '/'), $home)) {
                $foreign[] = $reflection->getName();
            }
        }

        if ([] === $foreign) {
            return;
        }

        // Toutes les définitions sont parcourues, et pas les seules marquées : une classe qui
        // implémente le contrat sans la marque serait autrement ignorée, et son auteur croirait
        // son moyen compté.
        throw new LogicException(\sprintf("Ces services implémentent %s sans appartenir à ce paquet :\n  - %s\nUn moyen d'authentification n'est pas un point d'extension : ce qui compte comme protection est vérifié par ce qui l'a écrit.\nAllumer le mécanisme voulu sous « authentication_policy.mechanisms », ou retirer ces classes.", Factor::class, implode("\n  - ", array_values(array_unique($foreign)))));
    }
}
