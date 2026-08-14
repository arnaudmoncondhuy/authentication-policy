<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\InspectHardenedDefaultsPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\PolicyFactory;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseDeadExemptionPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseDelegationWithoutStorePass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseLockWithoutExitPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseUnboundedDurationPass;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

/**
 * Le point de montage du paquet.
 *
 * Reste à la racine de `src/` : {@see AbstractBundle::getPath()} calcule le chemin du paquet en
 * remontant de deux dossiers depuis ce fichier, et c'est ce qui rend `../config/` juste.
 *
 * Le paquet s'installe sans qu'on écrive quoi que ce soit : sans configuration, chaque réglage
 * garde sa valeur la plus permissive, aucun verrou ne se ferme, et rien ne change. Ce qui est
 * exigé est exigé parce qu'on l'a écrit.
 */
final class AuthenticationPolicyBundle extends AbstractBundle
{
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        // Les trois garanties. Chacune arrête la compilation, et aucune n'a de contournement :
        // ce qui est refusé ici ne démarre pas, y compris sur le poste de qui l'a écrit.
        $container->addCompilerPass(new RefuseDelegationWithoutStorePass());
        $container->addCompilerPass(new RefuseUnboundedDurationPass());
        $container->addCompilerPass(new RefuseLockWithoutExitPass());
        $container->addCompilerPass(new RefuseDeadExemptionPass());

        // Celle-ci ne refuse rien : elle relève ce qui n'appartient pas au paquet, et que
        // `authentication-policy:doctor` rend.
        $container->addCompilerPass(new InspectHardenedDefaultsPass());
    }

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('enrollment_path')
                    ->defaultNull()
                    ->info('Le chemin où le verrou renvoie ceux qui n\'ont pas posé ce que la politique exige.')
                    ->validate()
                        ->ifTrue(static fn (mixed $path): bool => !\is_string($path) || !str_starts_with($path, '/'))
                        ->thenInvalid('Le chemin d\'enrôlement commence par « / » : c\'est un chemin, pas une route.')
                    ->end()
                ->end()
                ->arrayNode('settings')
                    ->info('Un plafond par réglage, et les niveaux autorisés à le resserrer.')
                    ->useAttributeAsKey('name')
                    ->arrayPrototype()
                        ->children()
                            ->variableNode('ceiling')
                                ->defaultNull()
                                ->info('Le point de départ : un booléen, ou un nombre de secondes pour une durée. '
                                    .'Absent, c\'est la valeur la plus permissive — ce qu\'une passe refuse pour une durée déléguée.')
                            ->end()
                            ->arrayNode('delegated_to')
                                ->info('Qui peut resserrer ensuite : « role », « user », ou les deux.')
                                ->scalarPrototype()->end()
                                ->defaultValue([])
                                ->validate()
                                    ->ifTrue(static fn (mixed $deciders): bool => \is_array($deciders)
                                        && [] !== array_diff($deciders, ['role', 'user']))
                                    ->thenInvalid('Seuls « role » et « user » se délèguent : la configuration parle toujours en premier.')
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;
    }

    /**
     * @param array<array-key, mixed> $config la configuration du bundle, telle que
     *                                        {@see self::configure()} la décrit
     */
    public function loadExtension(array $config, ContainerConfigurator $configurator, ContainerBuilder $container): void
    {
        /** @var array<string, array{ceiling: bool|int, delegated_to: list<string>}> $settings */
        $settings = $config['settings'] ?? [];

        // Construite ici et jetée : c'est la seule façon de faire échouer la configuration à
        // l'endroit où on l'écrit, plutôt qu'au premier chargement de page. Une durée écrite en
        // chaîne, un réglage inconnu, un plafond du mauvais type y sont refusés.
        $policy = PolicyFactory::fromArray($settings);

        $path = $config['enrollment_path'] ?? null;

        $container->setParameter(Parameter::RULES, $settings);
        $container->setParameter(Parameter::ENROLLMENT_PATH, $path);

        $configurator->import('../config/policy.php');

        /** @var array<string, class-string> $bundles */
        $bundles = $container->getParameter('kernel.bundles');

        if (isset($bundles['SecurityBundle'])) {
            $configurator->import('../config/security.php');

            // Le verrou n'est monté que si la politique peut se fermer. Autrement il réclamerait
            // le service qui dit qui s'est enrôlé, alors qu'aucune application n'aurait de
            // raison de l'écrire.
            if ($policy->canRequire(Setting::TwoFactor)) {
                $configurator->import('../config/enrollment.php');
            }
        }

        if (class_exists(Command::class)) {
            $configurator->import('../config/console.php');
        }
    }
}
