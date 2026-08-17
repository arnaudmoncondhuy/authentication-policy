<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/**
 * Refuse de compiler le conteneur si le paquet gouverne sans savoir qui.
 *
 * Le périmètre nomme les pare-feux d'humains. Vide, il ne couvre rien : le verrou ne se ferme
 * sur personne, aucune session ne tombe, aucun écran ne répond. C'est le bon défaut pour un
 * paquet installé et pas encore réglé — et la pire des configurations dès que quelque chose est
 * allumé, puisque tout paraît en place et que rien ne s'applique.
 *
 * Un nom de pare-feu qui n'existe pas produit exactement le même silence, et se glisse au
 * moindre renommage.
 */
final readonly class RefusePerimeterlessPolicyPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasParameter(Parameter::FIREWALLS)) {
            return;
        }

        /** @var list<string> $named */
        $named = $container->getParameter(Parameter::FIREWALLS);

        if (!$this->governsSomething($container)) {
            return;
        }

        if ([] === $named) {
            throw new LogicException("Ce paquet est réglé pour gouverner quelque chose, mais aucun pare-feu ne lui est confié.\nSans périmètre il ne couvre rien : le verrou ne se ferme sur personne, les sessions ne tombent pas, et les écrans refusent de répondre — sans qu'aucune erreur le dise.\nNommer le ou les pare-feux des personnes sous « authentication_policy.firewalls ». L'entrée des machines n'y figure pas.");
        }

        $declared = $this->declaredFirewalls($container);

        if ([] === $declared) {
            return;
        }

        $unknown = array_diff($named, $declared);

        if ([] !== $unknown) {
            throw new LogicException(\sprintf("Ces pare-feux sont confiés à ce paquet et n'existent pas :\n  - %s\nConnus : %s.\nUn nom qui ne désigne rien laisse le paquet sans prise, en silence — c'est ce que produit un renommage oublié.", implode("\n  - ", $unknown), implode(', ', $declared)));
        }
    }

    /**
     * Le paquet gouverne dès qu'il peut exiger un second facteur, borner une durée, ou qu'un
     * mécanisme est allumé. Un paquet installé sans rien régler ne gouverne rien, et n'a donc
     * pas de périmètre à réclamer.
     */
    private function governsSomething(ContainerBuilder $container): bool
    {
        if ($container->hasParameter(Parameter::MECHANISMS)) {
            /** @var array<string, array{enabled: bool}> $mechanisms */
            $mechanisms = $container->getParameter(Parameter::MECHANISMS);

            foreach ($mechanisms as $mechanism) {
                if ($mechanism['enabled']) {
                    return true;
                }
            }
        }

        if (!$container->hasParameter(Parameter::RULES)) {
            return false;
        }

        /** @var array<string, array{ceiling: bool|int, delegated_to: list<string>}> $rules */
        $rules = $container->getParameter(Parameter::RULES);
        $policy = PolicyFactory::fromArray($rules);

        foreach ([Setting::IdleTimeout, Setting::AbsoluteTimeout] as $duration) {
            if (\PHP_INT_MAX !== $policy->ruleFor($duration)->ceiling) {
                return true;
            }
        }

        return $policy->canRequire(Setting::TwoFactor);
    }

    /**
     * Les pare-feux que la configuration de sécurité déclare.
     *
     * Une application sans SecurityBundle n'en déclare aucun, et le contrôle des noms se tait :
     * il n'aurait rien à quoi les comparer.
     *
     * @return list<string>
     */
    private function declaredFirewalls(ContainerBuilder $container): array
    {
        $declared = [];

        foreach ($container->getExtensionConfig('security') as $configuration) {
            if (!\is_array($configuration['firewalls'] ?? null)) {
                continue;
            }

            foreach (array_keys($configuration['firewalls']) as $name) {
                $declared[] = (string) $name;
            }
        }

        return array_values(array_unique($declared));
    }
}
