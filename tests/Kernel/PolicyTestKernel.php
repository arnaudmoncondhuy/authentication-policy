<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Kernel;

use ArnaudMoncondhuy\AuthenticationPolicy\AuthenticationPolicyBundle;
use ArnaudMoncondhuy\AuthenticationPolicy\Enrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\ApplicationFactor;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\FrozenClock;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryBackupCodeStore;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryRolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\EnrollmentController;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\GuardedController;
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

    /**
     * @param array<string, mixed> $policy   la configuration du bundle, telle qu'on l'écrirait
     * @param bool                 $stores   branche les contrats que la politique réclame
     * @param list<string>         $enrolled qui a déjà posé son second facteur
     */
    public function __construct(
        private readonly array $policy = [],
        private readonly bool $stores = true,
        private readonly array $enrolled = [],
        private readonly bool $twig = false,
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
            hash('xxh128', serialize([$this->policy, $this->stores, $this->enrolled, self::sourceStamp()])),
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

        $container->loadFromExtension('security', [
            'password_hashers' => ['Symfony\Component\Security\Core\User\InMemoryUser' => ['algorithm' => 'plaintext']],
            'providers' => ['memoire' => ['memory' => ['users' => [
                'arnaud' => ['password' => 'secret', 'roles' => ['ROLE_ADMIN']],
            ]]]],
            'firewalls' => ['main' => [
                'pattern' => '^/',
                'provider' => 'memoire',
                // Comme toute application réelle : le pare-feu ne charge le jeton que si
                // quelqu'un le lit.
                'lazy' => true,
                'http_basic' => true,
                'login_throttling' => ['max_attempts' => 5],
            ]],
            'access_control' => [['path' => '^/', 'roles' => 'PUBLIC_ACCESS']],
        ]);

        if ($this->twig) {
            $container->loadFromExtension('twig', ['default_path' => __DIR__.'/../Fixture/Web/templates']);
            $container->register(InMemoryBackupCodeStore::class)->setPublic(true);
            $container->register(ApplicationFactor::class)->setPublic(true)->setAutoconfigured(true);
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

        if (!$this->stores) {
            return;
        }

        $container->register(InMemoryRolePolicies::class)
            ->setArguments([['ROLE_ADMIN' => ['two_factor' => true]]]);
        $container->setAlias(RolePolicies::class, InMemoryRolePolicies::class);

        $container->register(InMemoryEnrollment::class)->setArguments([$this->enrolled]);
        $container->setAlias(Enrollment::class, InMemoryEnrollment::class);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('page', '/une-page')->controller(GuardedController::class);
        $routes->add('enrolement', '/enrolement')->controller(EnrollmentController::class);

        if ($this->twig) {
            $routes->import(__DIR__.'/../../config/routes.php');
        }
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
