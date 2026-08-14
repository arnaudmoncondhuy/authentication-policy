<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/**
 * Refuse de compiler le conteneur si une dispense du verrou est posée ailleurs que sur une
 * porte.
 *
 * Seconde moitié de la première garantie. Le verrou étant fermé par défaut, la seule façon de
 * lui échapper est {@see DuringEnrollment} — et une dispense qui ne s'applique à rien est pire
 * qu'inutile : elle donne le sentiment d'avoir rouvert une page qui reste fermée. On ne s'en
 * aperçoit qu'en essayant de s'enrôler, c'est-à-dire au pire moment.
 *
 * **Les portes ne se déclarent pas : Symfony les marque déjà.** Un contrôleur porte
 * `controller.service_arguments`, une commande `console.command`, un consommateur de message
 * `messenger.message_handler`. Une application qui ouvre une porte d'un autre genre ajoute sa
 * marque par le paramètre `authentication_policy.surface_tags`.
 *
 * La limite de ce contrôle est celle du conteneur : il ne voit que des services. Une classe
 * qu'aucun service ne désigne échappe à son regard — mais elle n'est alors atteinte par aucune
 * requête, et n'avait pas besoin de dispense.
 */
final readonly class RefuseDeadExemptionPass implements CompilerPassInterface
{
    /**
     * Les marques que le framework pose de lui-même sur ses portes d'entrée.
     *
     * @var list<string>
     */
    private const array FRAMEWORK_TAGS = [
        'controller.service_arguments',
        'console.command',
        'messenger.message_handler',
    ];

    public function process(ContainerBuilder $container): void
    {
        $surfaces = $this->surfaces($container);
        $dead = [];

        foreach ($container->getDefinitions() as $id => $definition) {
            $class = $definition->getClass() ?? $id;
            $reflection = $container->getReflectionClass($class, false);

            if (!$reflection instanceof \ReflectionClass || self::comesFromADependency($reflection)) {
                continue;
            }

            if (!self::carriesTheExemption($reflection) || isset($surfaces[$reflection->getName()])) {
                continue;
            }

            $dead[] = $reflection->getName();
        }

        $dead = array_values(array_unique($dead));

        if ([] !== $dead) {
            throw new LogicException(\sprintf("Ces classes portent une dispense du verrou d'enrôlement sans être des portes d'entrée :\n  - %s\nLa dispense n'y produit aucun effet, et laisse croire qu'une page est joignable pendant l'enrôlement. La poser sur la porte elle-même, ou la retirer.", implode("\n  - ", $dead)));
        }
    }

    /**
     * Les classes que le conteneur désigne comme portes, par le nom.
     *
     * @return array<string, true>
     */
    private function surfaces(ContainerBuilder $container): array
    {
        $tags = self::FRAMEWORK_TAGS;

        if ($container->hasParameter(Parameter::EXTRA_SURFACE_TAGS)) {
            /** @var list<string> $extra */
            $extra = (array) $container->getParameter(Parameter::EXTRA_SURFACE_TAGS);
            $tags = array_values(array_unique([...$tags, ...$extra]));
        }

        $surfaces = [];

        foreach ($tags as $tag) {
            foreach (array_keys($container->findTaggedServiceIds($tag)) as $service) {
                $class = $container->findDefinition($service)->getClass() ?? $service;
                $surfaces[$class] = true;
            }
        }

        return $surfaces;
    }

    /** @param \ReflectionClass<object> $reflection */
    private static function carriesTheExemption(\ReflectionClass $reflection): bool
    {
        if ([] !== $reflection->getAttributes(DuringEnrollment::class)) {
            return true;
        }

        foreach ($reflection->getMethods() as $method) {
            if ([] !== $method->getAttributes(DuringEnrollment::class)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Une classe livrée par une dépendance n'est pas la vôtre à gouverner.
     *
     * Le critère est le chemin du fichier, et sa limite est écrite plutôt que tue : un projet
     * qui aurait renommé son dossier de dépendances y échapperait.
     *
     * @param \ReflectionClass<object> $reflection
     */
    private static function comesFromADependency(\ReflectionClass $reflection): bool
    {
        $file = $reflection->getFileName();

        return false === $file || str_contains(strtr($file, '\\', '/'), '/vendor/');
    }
}
