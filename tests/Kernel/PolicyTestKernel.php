<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Kernel;

use ArnaudMoncondhuy\AuthenticationPolicy\AuthenticationPolicyBundle;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\FrozenClock;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\EnrollmentController;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\GuardedController;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\ProofController;
use Doctrine\DBAL\DriverManager;
use Psr\Clock\ClockInterface;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * Un vrai noyau, monté sur mesure pour chaque cas.
 *
 * C'est la seule chose qui prouve que le paquet est câblé : les passes éprouvées à la main
 * resteraient vertes même si plus rien ne les enregistrait, et un écouteur non déclaré ne
 * ferait échouer aucun test unitaire.
 */
final class PolicyTestKernel extends Kernel
{
    use MicroKernelTrait;

    /** Le nom sous lequel les cas nomment la connexion, dans `storage.connection`. */
    public const string CONNECTION = 'test.connection';

    /**
     * @param array<string, mixed> $policy         la configuration du bundle, telle qu'on l'écrirait
     * @param bool                 $ranged         monte une base en mémoire pour le rangement du paquet
     * @param bool                 $secondFirewall ajoute une entrée de machines, hors périmètre
     * @param list<class-string>   $extra          des services à enregistrer, pour éprouver un refus
     * @param bool                 $twoFactorStep  pose l'étape de second facteur sur le pare-feu
     */
    public function __construct(
        private readonly array $policy = [],
        private readonly bool $ranged = false,
        private readonly bool $twig = false,
        private readonly bool $secondFirewall = false,
        private readonly array $extra = [],
        private readonly bool $twoFactorStep = true,
    ) {
        // Hors mode debug : le noyau y écrirait chaque événement notifié sur la sortie d'erreur,
        // et la routine qualité deviendrait illisible. Ce que le debug apporte — reconstruire le
        // conteneur quand une source change — est obtenu par l'empreinte du dossier `src/`.
        parent::__construct('test', false);
    }

    /** @return iterable<object> */
    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        if ($this->twig) {
            yield new \Symfony\Bundle\TwigBundle\TwigBundle();
        }

        // L'étape de second facteur ne vient pas de ce paquet : elle vient de scheb, comme dans
        // toute application réelle. Sans elle, un mécanisme allumé se poserait sans que rien ne
        // le réclame à la connexion — ce qu'une passe refuse.
        if ($this->anyMechanismEnabled()) {
            yield new \Scheb\TwoFactorBundle\SchebTwoFactorBundle();
        }

        yield new AuthenticationPolicyBundle();
    }

    /**
     * Un dossier par cas, et par état des sources.
     *
     * L'empreinte porte sur la configuration du cas **et** sur la dernière modification du
     * paquet : sans elle, un conteneur mis en cache survivrait à un changement de code, et les
     * tests jugeraient une version qui n'existe plus.
     */
    public function getCacheDir(): string
    {
        return \sprintf(
            '%s/authentication-policy-tests/%s',
            sys_get_temp_dir(),
            hash('xxh128', serialize([
                $this->policy, $this->ranged, $this->twig, $this->secondFirewall, $this->extra,
                self::sourceStamp(),
            ])),
        );
    }

    public function getLogDir(): string
    {
        return $this->getCacheDir().'/log';
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'test' => true,
            'secret' => 'ce-qui-signe-les-cookies-du-test',
            'router' => ['utf8' => true],
            'http_method_override' => false,
            'session' => ['storage_factory_id' => 'session.storage.factory.mock_file'],
        ]);

        $firewalls = ['main' => [
            'pattern' => '^/',
            'provider' => 'memoire',
            // Comme toute application réelle : le pare-feu ne charge le jeton que si quelqu'un
            // le lit.
            'lazy' => true,
            'http_basic' => true,
            'login_throttling' => ['max_attempts' => 5],
        ]];

        if ($this->twoFactorStep && $this->anyMechanismEnabled()) {
            $firewalls['main']['two_factor'] = [
                'auth_form_path' => 'authentication_policy_login',
                'check_path' => 'authentication_policy_login_check',
            ];
        }

        if ($this->secondFirewall) {
            // L'entrée des machines : un pare-feu que le périmètre ne nomme pas. Il est déclaré
            // avant `main`, comme dans une application réelle où le motif le plus étroit passe
            // en premier.
            $firewalls = ['machines' => [
                'pattern' => '^/api',
                'provider' => 'memoire',
                'stateless' => true,
                'http_basic' => true,
            ]] + $firewalls;
        }

        $container->loadFromExtension('security', [
            'password_hashers' => ['Symfony\Component\Security\Core\User\InMemoryUser' => ['algorithm' => 'plaintext']],
            'providers' => ['memoire' => ['memory' => ['users' => [
                'arnaud' => ['password' => 'secret', 'roles' => ['ROLE_ADMIN']],
            ]]]],
            'firewalls' => $firewalls,
            'access_control' => [['path' => '^/', 'roles' => 'PUBLIC_ACCESS']],
        ]);

        if ($this->twig) {
            $container->loadFromExtension('twig', ['default_path' => __DIR__.'/../Fixture/Web/templates']);
        }

        if ($this->ranged) {
            // Une base en mémoire : les tables du paquet s'y créent seules, et disparaissent
            // avec le noyau.
            $container->register(self::CONNECTION, \Doctrine\DBAL\Connection::class)
                ->setFactory([DriverManager::class, 'getConnection'])
                ->setArguments([['driver' => 'pdo_sqlite', 'memory' => true]])
                ->setPublic(true);
        }

        foreach ($this->extra as $class) {
            $container->register($class)->setPublic(true);
        }

        $container->loadFromExtension('authentication_policy', $this->policy);

        // L'heure que le test avance à la main, publique pour qu'il l'atteigne.
        $container->register(FrozenClock::class)->setPublic(true);
        $container->setAlias(ClockInterface::class, FrozenClock::class)->setPublic(true);

        $container->register(GuardedController::class)
            ->setPublic(true)
            ->addTag('controller.service_arguments');

        $container->register(EnrollmentController::class)
            ->setPublic(true)
            ->addTag('controller.service_arguments');

        // La page qui interroge le juge du pont. Elle n'existe que si un mécanisme est allumé :
        // sans lui, le juge n'est pas déclaré, et la page ne se construirait pas.
        if ($this->anyMechanismEnabled()) {
            $container->register(ProofController::class)
                ->setAutowired(true)
                ->setPublic(true)
                ->addTag('controller.service_arguments');
        }
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('page', '/une-page')->controller(GuardedController::class);
        $routes->add('enrolement', '/enrolement')->controller(EnrollmentController::class);

        if ($this->anyMechanismEnabled()) {
            $routes->add('preuve', '/preuve')->controller(ProofController::class);
        }

        if ($this->secondFirewall) {
            $routes->add('machine', '/api/etat')->controller(GuardedController::class);
        }

        // Les écrans du paquet prennent leurs chemins ici, comme dans une application.
        $routes->import('.', 'authentication_policy');
    }

    private function anyMechanismEnabled(): bool
    {
        /** @var array<string, array{enabled?: bool}> $mechanisms */
        $mechanisms = $this->policy['mechanisms'] ?? [];

        foreach ($mechanisms as $mechanism) {
            if (true === ($mechanism['enabled'] ?? false)) {
                return true;
            }
        }

        return false;
    }

    /** La date de la source la plus récemment modifiée du paquet. */
    private static function sourceStamp(): int
    {
        $newest = 0;

        foreach (['/../../src', '/../../config'] as $directory) {
            $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__.$directory));

            foreach ($files as $file) {
                if ($file instanceof \SplFileInfo && $file->isFile()) {
                    $newest = max($newest, $file->getMTime());
                }
            }
        }

        return $newest;
    }
}
