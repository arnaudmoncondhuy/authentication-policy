<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Integration;

use ArnaudMoncondhuy\AuthenticationPolicy\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
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

    public function testEteintsRienNEstInstalle(): void
    {
        $container = $this->boot(['enabled' => false])->getContainer();

        self::assertFalse($container->has(BackupCodes::class));
        self::assertFalse($container->has(Factors::class));
    }

    public function testAllumesLeMecanismeEstLaEtSeCompteParmiLesMoyens(): void
    {
        $container = $this->boot()->getContainer();

        /** @var BackupCodes $backupCodes */
        $backupCodes = $container->get(BackupCodes::class);
        /** @var Factors $factors */
        $factors = $container->get(Factors::class);

        self::assertSame(1, $factors->countFor('arnaud'));

        $backupCodes->generateFor('arnaud');

        self::assertSame(BackupCodes::HOW_MANY + 1, $factors->countFor('arnaud'));
        self::assertSame(10, $factors->detailFor('arnaud')['backup_codes']);
    }

    /**
     * Le moyen que l'application écrit elle-même doit être compté sans qu'elle ait rien à
     * déclarer. Sans cela, le paquet croit un compte démuni, et le verrou se referme sur
     * quelqu'un qui a pourtant posé ce qu'on lui demandait.
     */
    public function testLeMoyenEcritParLApplicationEstCompteSansMarqueAPoser(): void
    {
        /** @var Factors $factors */
        $factors = $this->boot()->getContainer()->get(Factors::class);

        self::assertSame(1, $factors->countFor('arnaud'));
        self::assertArrayHasKey('quelque_chose_de_l_application', $factors->detailFor('arnaud'));
    }

    public function testLEcranSAfficheSansQueLApplicationNEcriveRien(): void
    {
        $response = $this->send($this->boot(), 'GET');

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
     * @param array<string,mixed>|null $backupCodes
     */
    private function boot(?array $backupCodes = null): PolicyTestKernel
    {
        $this->kernel?->shutdown();
        $this->kernel = new PolicyTestKernel(
            policy: ['backup_codes' => ($backupCodes ?? [
                'enabled' => true,
                'store' => InMemoryBackupCodeStore::class,
                'layout' => null,
            ])],
            twig: true,
        );
        $this->kernel->boot();

        return $this->kernel;
    }

    /**
     * @param array<string,string> $payload
     */
    private function send(PolicyTestKernel $kernel, string $method, array $payload = [], ?Response $previous = null): Response
    {
        $request = Request::create('/codes-de-secours', $method, $payload);
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

    /**
     * @return list<string>
     */
    private static function codesOf(string $html): array
    {
        preg_match_all('/<code>([0-9a-f-]+)<\/code>/', $html, $matches);

        return $matches[1];
    }
}
