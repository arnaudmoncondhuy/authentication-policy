<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\InspectHardenedDefaultsPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\PolicyFactory;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseDeadExemptionPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseDelegationWithoutStorePass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseForeignFactorPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseLockWithoutExitPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseMechanismWithoutTwoFactorListenerPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefusePerimeterlessPolicyPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseUnboundedDurationPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseUnprotectedRemovalPass;
use Doctrine\DBAL\Connection;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderInterface;
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
 * garde sa valeur la plus permissive, aucun mécanisme n'existe, aucun verrou ne se ferme. Ce
 * qui est exigé est exigé parce qu'on l'a écrit.
 */
final class AuthenticationPolicyBundle extends AbstractBundle
{
    /**
     * Les mécanismes que ce paquet fabrique, et le fichier de services de chacun.
     *
     * La liste est fermée : un moyen d'authentification n'est pas un point d'extension. Ce qui
     * compte comme protection est vérifié par ce qui l'a écrit, faute de quoi le paquet
     * garantirait un compte protégé par un mécanisme dont il ne sait rien.
     *
     * @var array<string, string>
     */
    private const array MECHANISMS = [
        'totp' => 'totp',
        'security_key' => 'security_key',
        'backup_codes' => 'backup_codes',
    ];

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        // Les garanties. Chacune arrête la compilation, et aucune n'a de contournement : ce qui
        // est refusé ici ne démarre pas, y compris sur le poste de qui l'a écrit.
        $container->addCompilerPass(new RefuseDelegationWithoutStorePass());
        $container->addCompilerPass(new RefuseUnboundedDurationPass());
        $container->addCompilerPass(new RefuseLockWithoutExitPass());
        $container->addCompilerPass(new RefuseDeadExemptionPass());
        $container->addCompilerPass(new RefusePerimeterlessPolicyPass());
        $container->addCompilerPass(new RefuseForeignFactorPass());
        $container->addCompilerPass(new RefuseMechanismWithoutTwoFactorListenerPass());
        $container->addCompilerPass(new RefuseUnprotectedRemovalPass());

        // Celle-ci ne refuse rien : elle relève ce qui n'appartient pas au paquet, et que
        // `authentication-policy:doctor` rend.
        $container->addCompilerPass(new InspectHardenedDefaultsPass());
    }

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->arrayNode('firewalls')
                    ->info('Les pare-feux des personnes. Ce qui n\'y figure pas — l\'entrée des machines, les outils de développement — ne voit rien de ce paquet.')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                    ->validate()
                        ->ifTrue(static fn (mixed $names): bool => \is_array($names)
                            && [] !== array_filter($names, static fn (mixed $name): bool => !\is_string($name) || '' === $name))
                        ->thenInvalid('Un nom de pare-feu ne peut pas être vide.')
                    ->end()
                ->end()
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
                ->arrayNode('role_policies')
                    ->info('Ce que chaque rôle resserre, sans base ni classe à écrire. Un réglage inconnu arrête la compilation.')
                    ->useAttributeAsKey('role')
                    ->variablePrototype()->end()
                    ->defaultValue([])
                ->end()
                ->arrayNode('preferences')
                    ->info('Ce qu\'une personne choisit pour elle-même.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultTrue()
                            ->info('Éteintes, aucun choix personnel ne se range et l\'écran n\'en propose aucun.')
                        ->end()
                        ->scalarNode('store')
                            ->defaultNull()
                            ->info('Le service qui les range. Absent, le paquet les range dans une table à lui.')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('storage')
                    ->info('Où le paquet range ce que les mécanismes posent.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('connection')
                            ->defaultValue('doctrine.dbal.default_connection')
                            ->info('La connexion à employer.')
                        ->end()
                        ->scalarNode('table_prefix')
                            ->defaultValue('authentication_')
                            ->info('Le préfixe commun. Il permet d\'exclure toutes ces tables d\'un seul motif dans « doctrine.schema_filter ».')
                            ->validate()
                                ->ifTrue(static fn (mixed $prefix): bool => !\is_string($prefix)
                                    || 1 !== preg_match('/^[a-z][a-z0-9_]*$/', $prefix))
                                ->thenInvalid('Un préfixe de table s\'écrit en minuscules, sans espace, et commence par une lettre.')
                            ->end()
                        ->end()
                        ->booleanNode('auto_setup')
                            ->defaultTrue()
                            ->info('Créer les tables au premier usage. À couper là où le compte de base de données n\'a pas à posséder le schéma.')
                        ->end()
                    ->end()
                ->end()
                ->append($this->mechanisms())
                ->append($this->templates())
                ->append($this->routes())
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

        /** @var array<string, mixed> $rolePolicies */
        $rolePolicies = $config['role_policies'] ?? [];

        /** @var array<string, array{enabled: bool, store: string|null, ...}> $mechanisms */
        $mechanisms = $config['mechanisms'] ?? [];

        /** @var array{connection: string, table_prefix: non-empty-string, auto_setup: bool} $storage */
        $storage = $config['storage'];

        /** @var array{enabled: bool, store: string|null} $preferences */
        $preferences = $config['preferences'];

        /** @var array<string, string|null> $templates */
        $templates = $config['templates'];

        $this->guardRelyingPartyName($mechanisms);

        $container->setParameter(Parameter::RULES, $settings);
        $container->setParameter(Parameter::ROLE_POLICIES, PolicyFactory::rolePoliciesFromArray($rolePolicies));
        $container->setParameter(Parameter::TWO_FACTOR_REQUIRABLE, $policy->canRequire(Setting::TwoFactor));
        $container->setParameter(Parameter::ENROLLMENT_PATH, $config['enrollment_path'] ?? null);
        $container->setParameter(Parameter::FIREWALLS, array_values($config['firewalls'] ?? []));
        $container->setParameter(Parameter::TABLE_PREFIX, $storage['table_prefix']);
        $container->setParameter(Parameter::AUTO_SETUP, $storage['auto_setup']);
        $container->setParameter(Parameter::MECHANISMS, $mechanisms);
        $container->setParameter(Parameter::ROUTES, $config['routes']);

        foreach ($templates as $screen => $template) {
            $container->setParameter(Parameter::TEMPLATE.'.'.$screen, $template);
        }

        // Un paramètre par réglage, en plus du tableau : c'est ce qu'un fichier de services sait
        // injecter dans un argument.
        foreach ($mechanisms as $name => $options) {
            foreach ($options as $option => $value) {
                $container->setParameter(\sprintf('%s.%s.%s', Parameter::MECHANISM, $name, $option), $value);
            }
        }

        $configurator->import('../config/policy.php');
        $configurator->import('../config/factors.php');

        // Les choix personnels ne se rangent que s'il y a quelque chose à choisir : une
        // politique qui ne délègue rien à la personne n'a aucune préférence à retenir, et
        // réclamer une base pour l'occasion rendrait le paquet ininstallable sans Doctrine.
        $chosen = $preferences['enabled'] && [] !== $policy->delegatedTo(Decider::User);

        if ($chosen && null !== $preferences['store']) {
            $container->setAlias(UserPreferences::class, $preferences['store']);
        }

        // Le rangement du paquet n'existe que si quelque chose s'y range. Un mécanisme qui
        // nomme son propre service, comme une application sans mécanisme, n'a besoin d'aucune
        // base de données.
        $ownRanging = $chosen && null === $preferences['store'];

        foreach (self::MECHANISMS as $name => $file) {
            $ownRanging = $ownRanging
                || (true === ($mechanisms[$name]['enabled'] ?? false) && null === ($mechanisms[$name]['store'] ?? null));
        }

        if ($ownRanging && class_exists(Connection::class)) {
            // Un alias plutôt qu'un paramètre : c'est un service que le rangement attend, et le
            // nom de la connexion n'est connu qu'ici.
            $container->setAlias(Parameter::CONNECTION, $storage['connection']);
            $configurator->import('../config/storage.php');

            if ($chosen && null === $preferences['store']) {
                $configurator->import('../config/preferences.php');
            }
        }

        /** @var array<string, class-string> $bundles */
        $bundles = $container->getParameter('kernel.bundles');
        $secured = isset($bundles['SecurityBundle']);

        if ($secured) {
            $configurator->import('../config/security.php');

            // Le verrou n'est monté que si la politique peut se fermer. Autrement il
            // surveillerait un enrôlement que rien n'exige.
            if ($policy->canRequire(Setting::TwoFactor)) {
                $configurator->import('../config/enrollment.php');
            }
        }

        // Les écrans réclament de quoi rendre une page. La classe suffit à l'analyse, pas au
        // conteneur : c'est le bundle enregistré qui donne le service.
        $screens = isset($bundles['TwigBundle']);

        if ($screens) {
            $configurator->import('../config/screens.php');
        }

        // L'étape de second facteur vient de scheb : le paquet la remplit, il ne la pose pas.
        // Sans lui, les mécanismes se posent et se comptent, mais rien ne les demande à la
        // connexion — ce que RefuseMechanismWithoutTwoFactorListenerPass refuse.
        $step = $secured && interface_exists(TwoFactorProviderInterface::class);
        $enabled = false;

        foreach (self::MECHANISMS as $name => $file) {
            if (true !== ($mechanisms[$name]['enabled'] ?? false)) {
                continue;
            }

            $enabled = true;

            $configurator->import(\sprintf('../config/mechanism_%s.php', $file));

            // Le rangement du mécanisme : celui de l'application si elle en nomme un, celui du
            // paquet sinon. Le premier ne se décrit même pas quand le second est nommé.
            $store = $mechanisms[$name]['store'] ?? null;

            if (null !== $store) {
                $container->setAlias(Parameter::STORE.'.'.$name, $store);
            } elseif (class_exists(Connection::class)) {
                $configurator->import(\sprintf('../config/mechanism_%s_storage.php', $file));
            }

            if ($screens) {
                $configurator->import(\sprintf('../config/mechanism_%s_screen.php', $file));
            }

            if ($step && $screens) {
                $configurator->import(\sprintf('../config/mechanism_%s_login.php', $file));
            }
        }

        $container->setParameter(Parameter::LOGIN_STEP, $enabled && $step);

        if ($secured) {
            $configurator->import('../config/routes.php');
        }

        if (class_exists(Command::class)) {
            $configurator->import('../config/console.php');
        }
    }

    /**
     * Le paquet donne son propre dossier de comportements à Stimulus, faute de quoi les écrans
     * qui en réclament un rendraient une page inerte.
     *
     * Le défaut du projet n'est ajouté que si personne ne l'a encore nommé : une application
     * qui a retiré ce chemin l'a fait exprès, et le lui rendre couperait ses propres
     * comportements sans rien dire.
     */
    public function prependExtension(ContainerConfigurator $configurator, ContainerBuilder $container): void
    {
        /** @var array<string, class-string> $bundles */
        $bundles = $container->getParameter('kernel.bundles');

        if (!isset($bundles['StimulusBundle'])) {
            return;
        }

        $paths = [$this->getPath().'/public/controllers'];
        $named = false;

        foreach ($container->getExtensionConfig('stimulus') as $configuration) {
            $named = $named || isset($configuration['controller_paths']);
        }

        if (!$named) {
            $projectDir = $container->getParameter('kernel.project_dir');
            $projectPath = \is_string($projectDir) ? $projectDir.'/assets/controllers' : null;

            // Le dossier peut ne pas exister : le chercheur de comportements lève sur un chemin
            // absent, et l'application ne démarrerait plus.
            if (null !== $projectPath && is_dir($projectPath)) {
                $paths[] = $projectPath;
            }
        }

        $container->prependExtensionConfig('stimulus', ['controller_paths' => $paths]);
    }

    /**
     * Un mécanisme éteint n'a ni service, ni table, ni écran, ni route. C'est ce qui permet
     * d'en fabriquer plusieurs sans que ceux qu'on n'emploie pas coûtent quoi que ce soit.
     */
    private function mechanisms(): \Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition
    {
        $builder = new \Symfony\Component\Config\Definition\Builder\TreeBuilder('mechanisms');
        $node = $builder->getRootNode();

        $node
            ->info('Les moyens de prouver qui l\'on est. Éteints tant qu\'on ne les allume pas.')
            ->addDefaultsIfNotSet()
            ->children()
                ->arrayNode('totp')
                    ->info('Le code à six chiffres d\'une application d\'authentification.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')->defaultFalse()->end()
                        ->scalarNode('issuer')
                            ->defaultNull()
                            ->info('Ce que l\'application d\'authentification affiche en gras — le nom du service.')
                        ->end()
                        ->scalarNode('server_name')
                            ->defaultNull()
                            ->info('Ce qui suit l\'identité dans la liste, pour distinguer deux installations du même service.')
                        ->end()
                        ->integerNode('digits')
                            ->defaultValue(6)
                            ->validate()
                                ->ifNotInArray([6, 8])
                                ->thenInvalid('Les applications d\'authentification ne lisent que 6 ou 8 chiffres.')
                            ->end()
                        ->end()
                        ->integerNode('period')->defaultValue(30)->min(1)->info('Secondes de validité d\'un code.')->end()
                        ->enumNode('algorithm')->values(['sha1', 'sha256', 'sha512'])->defaultValue('sha1')->end()
                        ->integerNode('leeway')
                            ->defaultValue(0)
                            ->min(0)
                            ->info('Secondes de tolérance de part et d\'autre, pour une horloge mal réglée.')
                        ->end()
                        ->scalarNode('store')->defaultNull()->info('Le service qui range les secrets.')->end()
                    ->end()
                    ->validate()
                        ->ifTrue(static fn (array $totp): bool => $totp['leeway'] >= $totp['period'])
                        ->thenInvalid('Une tolérance aussi longue que la période fait accepter indéfiniment le code précédent.')
                    ->end()
                ->end()
                ->arrayNode('security_key')
                    ->info('Les clés de sécurité : clé physique, empreinte, reconnaissance du visage, code de l\'appareil.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')->defaultFalse()->end()
                        ->scalarNode('relying_party_name')
                            ->defaultNull()
                            ->info('Le nom du site, tel que l\'appareil l\'affiche au moment de poser la clé. Obligatoire dès que le mécanisme est allumé.')
                        ->end()
                        ->scalarNode('relying_party_id')
                            ->defaultNull()
                            ->info('Le domaine auquel les clés sont liées. Absent, celui de la page. Une clé posée sous un domaine est invisible sous un autre.')
                        ->end()
                        ->arrayNode('allowed_origins')
                            ->info('Les origines acceptées en plus de celle de la requête.')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->integerNode('timeout')->defaultValue(60000)->min(1000)->info('Millisecondes laissées pour répondre.')->end()
                        ->enumNode('user_verification')->values(['required', 'preferred', 'discouraged'])->defaultValue('preferred')->end()
                        ->enumNode('resident_key')->values(['required', 'preferred', 'discouraged'])->defaultValue('discouraged')->end()
                        ->integerNode('label_max_length')->defaultValue(60)->min(8)->end()
                        ->scalarNode('store')->defaultNull()->info('Le service qui range les clés.')->end()
                    ->end()
                ->end()
                ->arrayNode('backup_codes')
                    ->info('Le moyen d\'entrer quand tous les autres sont perdus.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')->defaultFalse()->end()
                        ->integerNode('how_many')->defaultValue(10)->min(1)->max(50)->end()
                        ->integerNode('length')->defaultValue(8)->min(4)->max(32)->info('Octets tirés au sort par code.')->end()
                        ->scalarNode('store')->defaultNull()->info('Le service qui range les codes.')->end()
                    ->end()
                ->end()
            ->end()
        ;

        return $node;
    }

    /**
     * Deux voies de surcharge, et elles se cumulent : ces clés nomment un autre gabarit, et un
     * fichier du même nom sous `templates/bundles/AuthenticationPolicyBundle/` en remplace un
     * sans rien configurer. La clé l'emporte quand les deux existent.
     */
    private function templates(): \Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition
    {
        $builder = new \Symfony\Component\Config\Definition\Builder\TreeBuilder('templates');
        $node = $builder->getRootNode();

        $children = $node
            ->info('Le gabarit de chaque écran.')
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('layout')
                    ->defaultNull()
                    ->info('Le cadre dont les écrans héritent — le vôtre. Absent, le paquet en fournit un nu.')
                ->end()
                ->scalarNode('login_layout')
                    ->defaultNull()
                    ->info('Le cadre de l\'étape de connexion, où l\'on n\'a pas encore de navigation à offrir.')
                ->end()
        ;

        foreach (['security', 'totp', 'security_key', 'backup_codes'] as $screen) {
            $children->scalarNode($screen)->defaultValue(\sprintf('@AuthenticationPolicy/%s.html.twig', $screen))->end();
            $children->scalarNode('login_'.$screen)->defaultValue(\sprintf('@AuthenticationPolicy/login/%s.html.twig', $screen))->end();
        }

        $children->end();

        return $node;
    }

    private function routes(): \Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition
    {
        $builder = new \Symfony\Component\Config\Definition\Builder\TreeBuilder('routes');
        $node = $builder->getRootNode();

        $paths = [
            'security' => '',
            'totp' => '/application',
            'security_key' => '/cles',
            'backup_codes' => '/codes-de-secours',
            'login' => '/verification',
            'login_check' => '/verification/reponse',
        ];

        $children = $node
            ->info('Sous quels chemins les écrans du paquet vivent. Le chemin est ce que les gens retiennent.')
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('prefix')->defaultValue('/securite')->end()
        ;

        foreach ($paths as $route => $path) {
            $children->scalarNode($route)->defaultValue($path)->end();
        }

        $children->end();

        $node->validate()
            ->ifTrue(static fn (array $routes): bool => [] !== array_filter(
                $routes,
                static fn (mixed $path): bool => !\is_string($path) || ('' !== $path && !str_starts_with($path, '/')),
            ))
            ->thenInvalid('Un chemin de route commence par « / », ou reste vide pour se confondre avec le préfixe.')
        ->end();

        return $node;
    }

    /**
     * Le navigateur refuse une demande dont le site n'a pas de nom, et le message qu'il rend
     * ne dit pas laquelle des dix propriétés manque.
     *
     * @param array<string, array{enabled: bool, relying_party_name?: string|null}> $mechanisms
     */
    private function guardRelyingPartyName(array $mechanisms): void
    {
        $key = $mechanisms['security_key'] ?? ['enabled' => false];

        if (true !== $key['enabled'] || '' !== (string) ($key['relying_party_name'] ?? '')) {
            return;
        }

        throw new \InvalidArgumentException('Une clé de sécurité s\'enregistre sous un nom de site : l\'appareil l\'affiche au moment de la poser, et le navigateur refuse une demande sans nom. Renseigner « authentication_policy.mechanisms.security_key.relying_party_name ».');
    }
}
