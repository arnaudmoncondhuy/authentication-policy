<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Integration;

use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryBackupCodeStore;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Kernel\PolicyTestKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * Le montage complet du mécanisme dans une application qui démarre.
 *
 * Les tests unitaires appellent le mécanisme à la main : ils resteraient verts si le paquet
 * cessait de le brancher, de router son écran ou de le compter parmi les moyens.
 */
final class BackupCodesScreenTest extends TestCase
{
    private ?PolicyTestKernel $kernel = null;

    protected function tearDown(): void
    {
        $this->kernel?->shutdown();
        $this->kernel = null;
    }

    /**
     * Éteint, le mécanisme n'existe pas : ni service, ni écran, ni route. Le compte des moyens,
     * lui, demeure — c'est le cœur, et c'est lui qui répond zéro au verrou.
     */
    public function testEteintLeMecanismeNEstPasInstalleMaisLeCompteDemeure(): void
    {
        $container = $this->boot(['enabled' => false])->getContainer();

        self::assertFalse($container->has(BackupCodes::class));
        self::assertTrue($container->has(Factors::class));
    }

    public function testAllumesLeMecanismeEstLaEtSeCompteParmiLesMoyens(): void
    {
        $container = $this->boot()->getContainer();

        /** @var BackupCodes $backupCodes */
        $backupCodes = $container->get(BackupCodes::class);
        /** @var Factors $factors */
        $factors = $container->get(Factors::class);

        self::assertSame(0, $factors->countFor('arnaud'));

        $backupCodes->generateFor('arnaud');

        self::assertSame(BackupCodes::HOW_MANY, $factors->countFor('arnaud'));

        // Un seul mécanisme allumé, et il se nomme sous le nom que la configuration et les
        // traductions emploient : le changer est un changement de contrat, pas de nommage.
        self::assertSame(['backup_codes'], array_keys($factors->detailFor('arnaud')));
    }

    /**
     * L'écran de sécurité : ce qui protège le compte, ce qui lui manque, et où le régler. Il
     * doit tenir debout sans qu'aucun moyen ne soit posé — c'est même là qu'il a le plus à dire.
     */
    public function testLEcranDeSecuriteDitCeQuiManqueAvantQueCaNeCoute(): void
    {
        $page = (string) $this->visit($this->boot(), '/securite')->getContent();

        self::assertStringContainsString('Aucun moyen ne protège ce compte', $page);
        self::assertStringContainsString('/securite/codes-de-secours', $page);
    }

    public function testLEcranSAfficheSansQueLApplicationNEcriveRien(): void
    {
        $response = $this->send($this->boot(), 'GET');

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertStringContainsString('Codes de secours', (string) $response->getContent());
    }

    /**
     * Le gabarit se remplace sans toucher au paquet, et c'est ce qui permet à une application de
     * garder sa mise en page sans renoncer au mécanisme.
     */
    public function testUnGabaritNommeEnConfigurationPrendLaPlaceDeCeluiDuPaquet(): void
    {
        $kernel = $this->boot(templates: ['backup_codes' => 'codes_a_nous.html.twig']);

        self::assertStringContainsString(
            "l'écran de l'application",
            (string) $this->send($kernel, 'GET')->getContent(),
        );
    }

    /** Le chemin est ce que les gens retiennent : c'est à l'application de le décider. */
    public function testUnCheminNommeEnConfigurationDeplaceLEcran(): void
    {
        $kernel = $this->boot(routes: ['prefix' => '/coffre', 'backup_codes' => '/mes-codes']);

        $response = $this->visit($kernel, '/coffre/mes-codes');

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertStringContainsString('Codes de secours', (string) $response->getContent());
    }

    /**
     * Un formulaire rejoué depuis ailleurs poserait une série neuve à l'insu de la personne, et
     * périmerait celle qu'elle vient d'imprimer.
     */
    public function testUneDemandeSansJetonEstRefusee(): void
    {
        $kernel = $this->boot();

        $this->expectException(AccessDeniedException::class);

        $this->send($kernel, 'POST');
    }

    /**
     * Les codes ne sont lisibles qu'à l'instant où ils sont posés : c'est ce qui oblige à les
     * noter, et ce qui fait qu'une page revisitée ne les rend pas.
     */
    public function testLaSerieNEstLisibleQueLeJourOuOnLaPose(): void
    {
        $kernel = $this->boot();

        $ecran = $this->send($kernel, 'GET');
        $posee = $this->send($kernel, 'POST', ['_token' => self::tokenOf((string) $ecran->getContent())], $ecran);

        self::assertSame(Response::HTTP_OK, $posee->getStatusCode());
        self::assertCount(BackupCodes::HOW_MANY, self::codesOf((string) $posee->getContent()));

        $revisitee = $this->send($kernel, 'GET', [], $posee);

        self::assertSame([], self::codesOf((string) $revisitee->getContent()));
        self::assertStringContainsString('codes restent utilisables', (string) $revisitee->getContent());
    }

    /**
     * @param array<string, mixed>|null $backupCodes
     * @param array<string, string>     $templates
     * @param array<string, string>     $routes
     */
    private function boot(?array $backupCodes = null, array $templates = [], array $routes = []): PolicyTestKernel
    {
        $this->kernel?->shutdown();

        $policy = [
            'firewalls' => ['main'],
            'mechanisms' => ['backup_codes' => $backupCodes ?? [
                'enabled' => true,
                'store' => InMemoryBackupCodeStore::class,
            ]],
        ];

        if ([] !== $templates) {
            $policy['templates'] = $templates;
        }

        if ([] !== $routes) {
            $policy['routes'] = $routes;
        }

        $this->kernel = new PolicyTestKernel($policy, twig: true, extra: [InMemoryBackupCodeStore::class]);
        $this->kernel->boot();

        return $this->kernel;
    }

    private function visit(PolicyTestKernel $kernel, string $path): Response
    {
        $request = Request::create($path);
        $request->headers->set('PHP_AUTH_USER', 'arnaud');
        $request->headers->set('PHP_AUTH_PW', 'secret');

        return $kernel->handle($request, HttpKernelInterface::MAIN_REQUEST, false);
    }

    /** @param array<string, string> $payload */
    private function send(PolicyTestKernel $kernel, string $method, array $payload = [], ?Response $previous = null): Response
    {
        $request = Request::create('/securite/codes-de-secours', $method, $payload);
        $request->headers->set('PHP_AUTH_USER', 'arnaud');
        $request->headers->set('PHP_AUTH_PW', 'secret');

        // La session voyage d'une requête à l'autre, comme le ferait un navigateur : sans elle,
        // le jeton lu à l'écran ne vaudrait plus rien à l'envoi.
        foreach ($previous?->headers->getCookies() ?? [] as $cookie) {
            $request->cookies->set($cookie->getName(), (string) $cookie->getValue());
        }

        return $kernel->handle($request, HttpKernelInterface::MAIN_REQUEST, false);
    }

    private static function tokenOf(string $html): string
    {
        preg_match('/name="_token" value="([^"]+)"/', $html, $matches);

        return $matches[1] ?? '';
    }

    /** @return list<string> */
    private static function codesOf(string $html): array
    {
        preg_match_all('/<code>([0-9a-f-]+)<\/code>/', $html, $matches);

        return $matches[1];
    }
}
