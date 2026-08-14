<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use ArnaudMoncondhuy\AuthenticationPolicy\Enrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/**
 * Refuse de compiler le conteneur si le verrou peut se fermer sans porte de sortie.
 *
 * Première moitié de la première garantie. Le verrou est fermé par défaut : dès que la
 * politique peut exiger un second facteur de quelqu'un, tout lui est refusé tant qu'il ne l'a
 * pas posé. Il faut donc deux choses, et leur absence ferme l'application à ceux qu'elle
 * concerne, sans recours et sans message :
 *
 * - un chemin où les envoyer, faute de quoi le verrou n'a nulle part où renvoyer ;
 * - un service qui sait dire si quelqu'un a posé son second facteur, faute de quoi la question
 *   n'a pas de réponse.
 *
 * La faute est de celles qui ne se découvrent qu'en production, sur le compte de la première
 * personne à qui la politique s'applique — souvent un administrateur, c'est-à-dire celui qui ne
 * peut plus rien réparer.
 */
final readonly class RefuseLockWithoutExitPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasParameter(Parameter::RULES)) {
            return;
        }

        /** @var array<string, array{ceiling: bool|int, delegated_to: list<string>}> $rules */
        $rules = $container->getParameter(Parameter::RULES);

        if (!PolicyFactory::fromArray($rules)->canRequire(Setting::TwoFactor)) {
            return;
        }

        $missing = [];

        if (null === $this->enrollmentPath($container)) {
            $missing[] =
                'le chemin d\'enrôlement (clé « enrollment_path »), où le verrou renvoie ceux qui n\'ont rien posé'
            ;
        }

        if (!$container->has(Enrollment::class)) {
            $missing[] = \sprintf(
                'un service implémentant %s, seul à savoir dire si quelqu\'un a posé son second facteur',
                Enrollment::class,
            );
        }

        if ([] !== $missing) {
            throw new LogicException(\sprintf("La politique peut exiger un second facteur, mais le verrou n'a pas de sortie :\n  - %s\nSans elle, les comptes concernés n'atteindraient plus aucune page, pas même celle qui les enrôle.", implode("\n  - ", $missing)));
        }
    }

    private function enrollmentPath(ContainerBuilder $container): ?string
    {
        if (!$container->hasParameter(Parameter::ENROLLMENT_PATH)) {
            return null;
        }

        $path = $container->getParameter(Parameter::ENROLLMENT_PATH);

        return \is_string($path) && '' !== $path ? $path : null;
    }
}
