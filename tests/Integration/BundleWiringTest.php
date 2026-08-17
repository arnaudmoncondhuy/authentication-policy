<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Integration;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\CurrentDecisions;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\ApplicationFactor;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Kernel\PolicyTestKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\Exception\LogicException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Ce qui ne se démontre qu'en démarrant une vraie application.
 *
 * Les tests unitaires appellent les passes et les écouteurs à la main : ils resteraient verts
 * si le bundle cessait de les enregistrer. Ceux-ci tombent.
 */
final class BundleWiringTest extends TestCase
{
    /** @var list<PolicyTestKernel> */
    private array $kernels = [];

    protected function tearDown(): void
    {
        foreach ($this->kernels as $kernel) {
            $kernel->shutdown();
        }

        $this->kernels = [];
    }

    public function testLePaquetSInstalleSansAucuneConfiguration(): void
    {
        $container = $this->boot()->getContainer();

        self::assertTrue($container->has(CurrentDecisions::class));
    }

    public function testLeVerrouFermeUnePageQuiNeDeclareRien(): void
    {
        $response = $this->request('/une-page', $this->lockingPolicy());

        self::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        self::assertSame('/enrolement', $response->headers->get('Location'));
    }

    public function testLaPageQuiEnroleResteJoignable(): void
    {
        $response = $this->request('/enrolement', $this->lockingPolicy());

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertSame('la page qui enrôle', $response->getContent());
    }

    public function testQuiAPoseUnMoyenTraverse(): void
    {
        $kernel = $this->boot($this->lockingPolicy(), ranged: true);

        /** @var BackupCodes $backupCodes */
        $backupCodes = $kernel->getContainer()->get(BackupCodes::class);
        $backupCodes->generateFor('arnaud');

        $response = $kernel->handle($this->signed('/une-page'), HttpKernelInterface::MAIN_REQUEST, false);

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertSame('la page ordinaire', $response->getContent());
    }

    public function testSansExigenceLeVerrouNeSeFermePas(): void
    {
        $response = $this->request('/une-page', ['settings' => ['two_factor' => ['ceiling' => false]]]);

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
    }

    /**
     * La garantie n'existe que si elle arrête vraiment la compilation d'une application. Une
     * passe qu'on appelle à la main dans un test unitaire ne prouve rien de cela.
     */
    public function testDeleguerSansStockageEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/UserPreferences/');

        $this->boot([
            'preferences' => ['enabled' => false],
            'settings' => ['two_factor' => ['ceiling' => false, 'delegated_to' => ['user']]],
        ]);
    }

    public function testUnVerrouSansCheminEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/enrollment_path/');

        $this->boot(['settings' => ['two_factor' => ['ceiling' => true]]]);
    }

    /**
     * Un verrou qui se ferme alors qu'aucun mécanisme n'est allumé enferme dehors : la page
     * d'enrôlement n'annonce alors que le vide.
     */
    public function testUnVerrouSansMecanismeEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/mechanisms/');

        $this->boot([
            'enrollment_path' => '/enrolement',
            'firewalls' => ['main'],
            'settings' => ['two_factor' => ['ceiling' => true]],
        ]);
    }

    public function testUneDureeDelegueeSansPlafondEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/idle_timeout/');

        $this->boot(['settings' => ['idle_timeout' => ['delegated_to' => ['role']]]]);
    }

    /**
     * Sans périmètre, tout paraît en place et rien ne s'applique : c'est la configuration la
     * plus dangereuse, puisqu'elle ne produit aucun symptôme.
     */
    public function testGouvernerSansPerimetreEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/firewalls/');

        $this->boot(['mechanisms' => ['backup_codes' => ['enabled' => true]]], ranged: true);
    }

    public function testUnPareFeuQuiNExistePasEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/machines/');

        $this->boot([
            'firewalls' => ['machines'],
            'mechanisms' => ['backup_codes' => ['enabled' => true]],
        ], ranged: true);
    }

    /**
     * Un mécanisme que rien ne réclame à la connexion se pose, se compte, ouvre le verrou — et
     * ne sert jamais. Rien à l'usage ne le signale : c'est une fausse confiance, et c'est la
     * pire des fautes que ce paquet puisse laisser passer.
     */
    public function testUnMecanismeQueRienNeReclameEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/auth_form_path/');

        $this->boot([
            'firewalls' => ['main'],
            'mechanisms' => ['backup_codes' => ['enabled' => true]],
        ], ranged: true, twoFactorStep: false);
    }

    /**
     * Un moyen d'authentification n'est pas un point d'extension : compté sans être vérifié par
     * le paquet, il ferait garantir un compte protégé par un mécanisme dont il ne sait rien.
     */
    public function testUnMoyenEcritParLApplicationEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/ApplicationFactor/');

        $this->boot(extra: [ApplicationFactor::class]);
    }

    /** @return array<string, mixed> */
    private function lockingPolicy(): array
    {
        return [
            'enrollment_path' => '/enrolement',
            'firewalls' => ['main'],
            'settings' => ['two_factor' => ['ceiling' => false, 'delegated_to' => ['role']]],
            'role_policies' => ['ROLE_ADMIN' => ['two_factor' => true]],
            'mechanisms' => ['backup_codes' => ['enabled' => true]],
        ];
    }

    private function signed(string $path): Request
    {
        $request = Request::create($path);
        $request->headers->set('PHP_AUTH_USER', 'arnaud');
        $request->headers->set('PHP_AUTH_PW', 'secret');

        return $request;
    }

    /** @param array<string, mixed> $policy */
    private function request(string $path, array $policy = []): Response
    {
        $ranged = [] !== ($policy['mechanisms'] ?? []);

        return $this->boot($policy, ranged: $ranged)
            ->handle($this->signed($path), HttpKernelInterface::MAIN_REQUEST, false);
    }

    /**
     * @param array<string, mixed> $policy
     * @param list<class-string>   $extra
     */
    private function boot(
        array $policy = [],
        bool $ranged = false,
        array $extra = [],
        bool $twoFactorStep = true,
    ): PolicyTestKernel {
        if ($ranged) {
            $policy['storage']['connection'] = PolicyTestKernel::CONNECTION;
        }

        $kernel = new PolicyTestKernel($policy, $ranged, extra: $extra, twoFactorStep: $twoFactorStep);
        $this->kernels[] = $kernel;
        $kernel->boot();

        return $kernel;
    }
}
