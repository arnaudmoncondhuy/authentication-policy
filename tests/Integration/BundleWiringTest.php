<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Integration;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\CurrentDecisions;
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

    public function testQuiSEstEnroleTraverse(): void
    {
        $response = $this->request('/une-page', $this->lockingPolicy(), enrolled: ['arnaud']);

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
        $this->expectExceptionMessageMatches('/RolePolicies/');

        $this->boot(
            ['settings' => ['two_factor' => ['ceiling' => false, 'delegated_to' => ['role']]]],
            stores: false,
        );
    }

    public function testUnVerrouSansCheminEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/enrollment_path/');

        $this->boot(['settings' => ['two_factor' => ['ceiling' => true]]]);
    }

    public function testUneDureeDelegueeSansPlafondEmpecheLApplicationDeDemarrer(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/idle_timeout/');

        $this->boot(['settings' => ['idle_timeout' => ['delegated_to' => ['role']]]]);
    }

    /** @return array<string, mixed> */
    private function lockingPolicy(): array
    {
        return [
            'enrollment_path' => '/enrolement',
            'settings' => ['two_factor' => ['ceiling' => false, 'delegated_to' => ['role']]],
        ];
    }

    /**
     * @param array<string, mixed> $policy
     * @param list<string>         $enrolled
     */
    private function request(string $path, array $policy = [], array $enrolled = []): Response
    {
        $kernel = $this->boot($policy, enrolled: $enrolled);

        $request = Request::create($path);
        $request->headers->set('PHP_AUTH_USER', 'arnaud');
        $request->headers->set('PHP_AUTH_PW', 'secret');

        return $kernel->handle($request, HttpKernelInterface::MAIN_REQUEST, false);
    }

    /**
     * @param array<string, mixed> $policy
     * @param list<string>         $enrolled
     */
    private function boot(array $policy = [], bool $stores = true, array $enrolled = []): PolicyTestKernel
    {
        $kernel = new PolicyTestKernel($policy, $stores, $enrolled);
        $this->kernels[] = $kernel;
        $kernel->boot();

        return $kernel;
    }
}
