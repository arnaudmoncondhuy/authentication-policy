<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Integration;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ReproveController;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryBackupCodeStore;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Kernel\PolicyTestKernel;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/**
 * Le pont vers le paquet d'autorisation, monté dans une application qui démarre.
 *
 * Ce qu'un test unitaire ne dit pas : que le contrat est bien branché sous l'alias que le
 * paquet voisin interroge, que l'écran de redemande a une route, et qu'une bonne réponse
 * rend la fraîcheur.
 */
final class ProofBridgeTest extends TestCase
{
    private ?PolicyTestKernel $kernel = null;

    /**
     * Le bocal à biscuits du navigateur imaginaire.
     *
     * Chaînée d'une requête à l'autre plutôt que reprise de la réponse précédente : une réponse
     * ne repose le cookie de session que si celle-ci vient de naître, et une redirection n'en
     * porte donc aucun.
     *
     * @var array<string, string>
     */
    private array $cookies = [];

    protected function tearDown(): void
    {
        $this->kernel?->shutdown();
        $this->kernel = null;
        $this->cookies = [];
    }

    /**
     * Sans mécanisme, ce juge ne pourrait répondre que non : une action protégée deviendrait
     * inatteignable par tout le monde sans que rien ne le dise. Mieux vaut qu'il n'existe pas —
     * le paquet voisin refuse alors de compiler, et son message nomme la cause.
     */
    public function testWithoutAnyMechanismNothingJudgesAProof(): void
    {
        $container = $this->boot(enabled: false)->getContainer()->get('test.service_container');
        self::assertInstanceOf(ContainerInterface::class, $container);

        self::assertFalse($container->has(ProofOfIdentity::class));
    }

    public function testAMechanismBringsTheJudgeUnderTheContractOfTheOtherPackage(): void
    {
        $container = $this->boot()->getContainer()->get('test.service_container');
        self::assertInstanceOf(ContainerInterface::class, $container);

        self::assertTrue($container->has(ProofOfIdentity::class));
        self::assertTrue($container->has(ReproveController::class));
    }

    /** Le compte est nu : rien n'est prouvé, et rien ne peut l'être. */
    public function testAnAccountWithoutAFactorMeetsNothing(): void
    {
        self::assertSame('strong=0 recent=0', $this->ask($this->boot()));
    }

    /** Un moyen posé vaut un moyen présenté, mais il ne vient pas de l'être. */
    public function testAnEquippedAccountIsStrongWithoutBeingRecent(): void
    {
        $kernel = $this->boot();
        $this->pose($kernel);

        self::assertSame('strong=1 recent=0', $this->ask($kernel));
    }

    /**
     * L'écran de redemande, atteignable et sachant dire ce qu'il attend. Sa route naît du
     * chargeur du paquet : aucune ligne à écrire dans l'application.
     */
    public function testTheScreenAsksForTheFactorThatIsPosed(): void
    {
        $kernel = $this->boot();
        $this->pose($kernel);

        $response = $this->visit($kernel, '/securite/confirmation');

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertStringContainsString('Confirmez que c’est bien vous', (string) $response->getContent());
        self::assertStringContainsString('Votre code', (string) $response->getContent());
    }

    /**
     * Le cas où l'exigence a été posée sur un compte nu : l'écran le dit, plutôt que d'afficher
     * un formulaire que rien ne pourrait satisfaire.
     */
    public function testTheScreenSaysSoWhenThereIsNothingToAskFor(): void
    {
        $response = $this->visit($this->boot(), '/securite/confirmation');

        self::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        self::assertStringContainsString('aucun moyen à présenter', (string) $response->getContent());
    }

    /** Une bonne réponse rend la fraîcheur, et ramène d'où l'on venait. */
    public function testARightAnswerMakesTheProofRecentAgain(): void
    {
        $kernel = $this->boot();
        $codes = $this->pose($kernel);

        $screen = $this->visit($kernel, '/securite/confirmation');

        $answered = $this->send($kernel, [
            '_token' => self::tokenOf((string) $screen->getContent()),
            'reponse' => $codes[0],
        ]);

        self::assertSame(Response::HTTP_FOUND, $answered->getStatusCode());
        self::assertSame('strong=1 recent=1', $this->ask($kernel));
    }

    /** Une mauvaise réponse ne rend rien, et laisse l'écran ouvert. */
    public function testAWrongAnswerChangesNothing(): void
    {
        $kernel = $this->boot();
        $this->pose($kernel);

        $screen = $this->visit($kernel, '/securite/confirmation');

        $answered = $this->send($kernel, [
            '_token' => self::tokenOf((string) $screen->getContent()),
            'reponse' => 'pas-le-bon',
        ]);

        self::assertSame(Response::HTTP_OK, $answered->getStatusCode());
        self::assertStringContainsString('pas la bonne réponse', (string) $answered->getContent());
        self::assertSame('strong=1 recent=0', $this->ask($kernel));
    }

    /**
     * Un formulaire rejoué depuis ailleurs poserait la preuve à l'insu de la personne, et
     * ouvrirait l'acte qu'elle protégeait.
     */
    public function testAnAnswerWithoutATokenIsRefused(): void
    {
        $kernel = $this->boot();
        $this->pose($kernel);

        $this->expectException(AccessDeniedException::class);

        $this->send($kernel, ['reponse' => 'peu importe']);
    }

    /** @return list<string> la série posée, dont un code servira à répondre */
    private function pose(PolicyTestKernel $kernel): array
    {
        $container = $kernel->getContainer();
        /** @var BackupCodes $backupCodes */
        $backupCodes = $container->get(BackupCodes::class);

        return $backupCodes->generateFor('arnaud');
    }

    /**
     * Ce que le juge répond, demandé depuis une page.
     *
     * Jamais depuis le test lui-même : la question n'a de sens que dans une requête, seule à
     * porter la session où vit la fraîcheur et le pare-feu qui situe l'appelant.
     */
    private function ask(PolicyTestKernel $kernel): string
    {
        return (string) $this->visit($kernel, '/preuve')->getContent();
    }

    private function boot(bool $enabled = true): PolicyTestKernel
    {
        $this->kernel?->shutdown();

        $this->kernel = new PolicyTestKernel(
            [
                'firewalls' => ['main'],
                'enrollment_path' => '/securite',
                'mechanisms' => ['backup_codes' => [
                    'enabled' => $enabled,
                    'store' => InMemoryBackupCodeStore::class,
                ]],
            ],
            twig: true,
            extra: [InMemoryBackupCodeStore::class],
        );
        $this->kernel->boot();

        return $this->kernel;
    }

    private function visit(PolicyTestKernel $kernel, string $path): Response
    {
        return $this->handle($kernel, $path, 'GET', []);
    }

    /** @param array<string, string> $payload */
    private function send(PolicyTestKernel $kernel, array $payload): Response
    {
        return $this->handle($kernel, '/securite/confirmation', 'POST', $payload);
    }

    /** @param array<string, string> $payload */
    private function handle(PolicyTestKernel $kernel, string $path, string $method, array $payload): Response
    {
        $request = Request::create($path, $method, $payload);
        $request->headers->set('PHP_AUTH_USER', 'arnaud');
        $request->headers->set('PHP_AUTH_PW', 'secret');
        $request->cookies->replace($this->cookies);

        $response = $kernel->handle($request, HttpKernelInterface::MAIN_REQUEST, false);

        foreach ($response->headers->getCookies() as $cookie) {
            $this->cookies[$cookie->getName()] = (string) $cookie->getValue();
        }

        return $response;
    }

    private static function tokenOf(string $html): string
    {
        preg_match('/name="_token" value="([^"]+)"/', $html, $matches);

        return $matches[1] ?? '';
    }
}
