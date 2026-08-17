<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Integration;

use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\FrozenClock;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryTotpSecrets;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Kernel\PolicyTestKernel;
use OTPHP\TOTP as Generator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Le parcours entier dans une application qui démarre : poser, confirmer, se voir compté.
 *
 * Les tests unitaires appellent le mécanisme à la main ; ils resteraient verts si le paquet
 * cessait de le brancher, de router son écran ou de le compter parmi les moyens.
 */
final class TotpScreenTest extends TestCase
{
    private ?PolicyTestKernel $kernel = null;

    protected function tearDown(): void
    {
        $this->kernel?->shutdown();
        $this->kernel = null;
    }

    public function testLEcranProposeDeCommencerEtRienNEstEcritEnLAffichant(): void
    {
        $kernel = $this->boot();

        $page = (string) $this->send($kernel, 'GET')->getContent();

        self::assertStringContainsString('Commencer', $page);
        self::assertNull($this->secrets($kernel)->secretOf('arnaud'));
    }

    public function testPoserPuisConfirmerFaitExisterLeMoyen(): void
    {
        $kernel = $this->boot();

        $this->act($kernel, 'start');
        $attente = $this->send($kernel, 'GET');
        $secret = $this->secrets($kernel)->secretOf('arnaud');

        self::assertNotNull($secret);
        // Le secret se recopie à la main quand l'appareil photo manque : trente-deux caractères.
        self::assertSame(32, \strlen($secret));
        self::assertStringContainsString('data:image/svg+xml', (string) $attente->getContent());
        self::assertSame(0, $this->factors($kernel)->countFor('arnaud'));

        $this->act($kernel, 'confirm', ['code' => $this->codeFor($kernel, $secret)]);

        self::assertSame(1, $this->factors($kernel)->countFor('arnaud'));
    }

    /**
     * Un chiffre mal recopié ne doit pas coûter toute la manipulation : le secret posé reste en
     * attente, et l'écran redemande le code.
     */
    public function testUnCodeFauxNeDefaitPasLEnrolementEnCours(): void
    {
        $kernel = $this->boot();

        $this->act($kernel, 'start');
        $secret = $this->secrets($kernel)->secretOf('arnaud');

        $refusee = $this->act($kernel, 'confirm', ['code' => '000000']);

        self::assertStringContainsString('ne correspond pas', (string) $refusee->getContent());
        self::assertSame($secret, $this->secrets($kernel)->secretOf('arnaud'));
    }

    /** Rafraîchir l'écran ne doit pas produire un second secret : l'appareil a déjà lu le bon. */
    public function testRevenirSurLEcranNePosePasUnSecondSecret(): void
    {
        $kernel = $this->boot();

        $this->act($kernel, 'start');
        $secret = $this->secrets($kernel)->secretOf('arnaud');

        $this->send($kernel, 'GET');
        $this->send($kernel, 'GET');

        self::assertSame($secret, $this->secrets($kernel)->secretOf('arnaud'));
    }

    public function testRetirerLeSeulMoyenEstRefuseALEcran(): void
    {
        $kernel = $this->boot(required: true);

        $this->act($kernel, 'start');
        $secret = $this->secrets($kernel)->secretOf('arnaud');

        self::assertNotNull($secret);

        $this->act($kernel, 'confirm', ['code' => $this->codeFor($kernel, $secret)]);

        $retire = $this->act($kernel, 'forget');

        self::assertStringContainsString('ne laisserait aucun moyen', (string) $retire->getContent());
        self::assertSame(1, $this->factors($kernel)->countFor('arnaud'));
    }

    /**
     * Un geste, comme un navigateur le ferait : lire l'écran pour son jeton, puis l'envoyer.
     *
     * @param array<string, string> $payload
     */
    private function act(PolicyTestKernel $kernel, string $geste, array $payload = []): Response
    {
        $ecran = $this->send($kernel, 'GET');

        return $this->send(
            $kernel,
            'POST',
            [...$payload, 'geste' => $geste, '_token' => self::tokenOf($ecran)],
            $ecran,
        );
    }

    private function boot(bool $required = false): PolicyTestKernel
    {
        $this->kernel?->shutdown();

        $policy = [
            'firewalls' => ['main'],
            'mechanisms' => ['totp' => [
                'enabled' => true,
                'issuer' => 'Le test',
                'store' => InMemoryTotpSecrets::class,
            ]],
        ];

        if ($required) {
            $policy['enrollment_path'] = '/securite';
            $policy['settings'] = ['two_factor' => ['ceiling' => true]];
        }

        $this->kernel = new PolicyTestKernel($policy, twig: true, extra: [InMemoryTotpSecrets::class]);
        $this->kernel->boot();

        return $this->kernel;
    }

    private function secrets(PolicyTestKernel $kernel): InMemoryTotpSecrets
    {
        /** @var InMemoryTotpSecrets $secrets */
        $secrets = $kernel->getContainer()->get(InMemoryTotpSecrets::class);

        return $secrets;
    }

    private function factors(PolicyTestKernel $kernel): Factors
    {
        /** @var Factors $factors */
        $factors = $kernel->getContainer()->get(Factors::class);

        return $factors;
    }

    /**
     * Le code qu'une application d'authentification afficherait à l'heure du noyau.
     *
     * @param non-empty-string $secret
     */
    private function codeFor(PolicyTestKernel $kernel, string $secret): string
    {
        /** @var FrozenClock $clock */
        $clock = $kernel->getContainer()->get(FrozenClock::class);

        return Generator::createFromSecret($secret, $clock)->now();
    }

    /** @param array<string, string> $payload */
    private function send(PolicyTestKernel $kernel, string $method, array $payload = [], ?Response $previous = null): Response
    {
        $request = Request::create('/securite/application', $method, $payload);
        $request->headers->set('PHP_AUTH_USER', 'arnaud');
        $request->headers->set('PHP_AUTH_PW', 'secret');

        foreach ($previous?->headers->getCookies() ?? [] as $cookie) {
            $request->cookies->set($cookie->getName(), (string) $cookie->getValue());
        }

        return $kernel->handle($request, HttpKernelInterface::MAIN_REQUEST, false);
    }

    private static function tokenOf(Response $response): string
    {
        preg_match('/name="_token" value="([^"]+)"/', (string) $response->getContent(), $matches);

        return $matches[1] ?? '';
    }
}
