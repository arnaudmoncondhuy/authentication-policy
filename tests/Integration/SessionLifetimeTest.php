<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Integration;

use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\FrozenClock;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Kernel\PolicyTestKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Les durées de session, éprouvées sur deux requêtes d'un vrai noyau.
 *
 * Le test unitaire pose lui-même l'état dans la session et appelle l'écouteur : il ne prouve
 * pas qu'une session ouverte par une vraie connexion porte cet état, ni qu'on le relit au bon
 * moment. C'est ce que celui-ci fait — et il le fait derrière un pare-feu **paresseux**, celui
 * de toutes les applications réelles, qui ne charge le jeton que si quelqu'un le lit.
 */
final class SessionLifetimeTest extends TestCase
{
    private ?PolicyTestKernel $kernel = null;

    protected function tearDown(): void
    {
        $this->kernel?->shutdown();
        $this->kernel = null;
    }

    public function testUneSessionSurvitTantQuOnSEnSert(): void
    {
        $cookies = $this->logIn();

        $this->clock()->advance(3599);

        self::assertSame(Response::HTTP_OK, $this->visit('/une-page', $cookies)->getStatusCode());
    }

    public function testUneSessionInactiveTropLongtempsNeRepondPlus(): void
    {
        $cookies = $this->logIn();

        $this->clock()->advance(3600);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $this->visit('/une-page', $cookies)->getStatusCode());
    }

    /** L'activité repousse l'inactivité, jamais la durée absolue. */
    public function testUneSessionActiveTombeAuBoutDeLaDureeAbsolue(): void
    {
        $cookies = $this->logIn();

        for ($i = 0; $i < 3; ++$i) {
            $this->clock()->advance(3500);
            self::assertSame(Response::HTTP_OK, $this->visit('/une-page', $cookies)->getStatusCode());
        }

        $this->clock()->advance(3500);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $this->visit('/une-page', $cookies)->getStatusCode());
    }

    /** @return array<string, string> */
    private function logIn(): array
    {
        $this->kernel = new PolicyTestKernel([
            'settings' => [
                'idle_timeout' => ['ceiling' => 3600],
                'absolute_timeout' => ['ceiling' => 14000],
            ],
        ]);
        $this->kernel->boot();

        $request = Request::create('/une-page');
        $request->headers->set('PHP_AUTH_USER', 'arnaud');
        $request->headers->set('PHP_AUTH_PW', 'secret');

        $response = $this->kernel->handle($request, HttpKernelInterface::MAIN_REQUEST, false);

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());

        $cookies = [];

        foreach ($response->headers->getCookies() as $cookie) {
            $cookies[$cookie->getName()] = (string) $cookie->getValue();
        }

        self::assertNotSame([], $cookies, 'La connexion n\'a ouvert aucune session.');

        return $cookies;
    }

    /** @param array<string, string> $cookies */
    private function visit(string $path, array $cookies): Response
    {
        $kernel = $this->kernel ?? self::fail('Aucun noyau démarré.');

        // Les exceptions sont rattrapées, comme en production : c'est l'écouteur du pare-feu
        // qui traduit un refus en réponse, et son point d'entrée qui choisit laquelle.
        return $kernel->handle(
            Request::create($path, 'GET', [], $cookies),
            HttpKernelInterface::MAIN_REQUEST,
            true,
        );
    }

    private function clock(): FrozenClock
    {
        $kernel = $this->kernel ?? self::fail('Aucun noyau démarré.');
        $clock = $kernel->getContainer()->get(FrozenClock::class);

        return $clock instanceof FrozenClock ? $clock : self::fail('L\'heure du test est introuvable.');
    }
}
