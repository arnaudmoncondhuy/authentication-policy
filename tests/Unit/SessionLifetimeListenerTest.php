<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\SessionLifetimeListener;
use ArnaudMoncondhuy\AuthenticationPolicy\Decider;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use ArnaudMoncondhuy\AuthenticationPolicy\Rule;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\FrozenClock;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryUserPreferences;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\StubFirewall;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Les deux durées, et ce qui les distingue : l'une vise le poste qu'on a quitté, l'autre la
 * session qui ne finit jamais parce qu'on s'en sert tous les jours.
 */
final class SessionLifetimeListenerTest extends TestCase
{
    private FrozenClock $clock;

    private TokenStorage $tokens;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->tokens = new TokenStorage();
        $this->tokens->setToken(
            new UsernamePasswordToken(new InMemoryUser('arnaud', null, ['ROLE_USER']), 'main', ['ROLE_USER']),
        );
    }

    public function testUneSessionActiveTraverse(): void
    {
        $session = $this->openedSession();

        $this->clock->advance(3599);
        $this->listener()->onRequest($this->requestEvent($session));

        self::assertSame(
            $this->clock->now()->getTimestamp(),
            $session->get(SessionLifetimeListener::SESSION_KEY)['seen_at'],
        );
    }

    public function testUneSessionInactiveTropLongtempsTombe(): void
    {
        $session = $this->openedSession();

        $this->clock->advance(3600);

        $this->expectException(AccessDeniedException::class);

        $this->listener()->onRequest($this->requestEvent($session));
    }

    /** L'activité repousse l'inactivité, jamais la durée absolue. */
    public function testUneSessionActiveTombeQuandMemeAuBoutDeLaDureeAbsolue(): void
    {
        $session = $this->openedSession();
        $listener = $this->listener();

        for ($i = 0; $i < 8; ++$i) {
            $this->clock->advance(3500);
            $listener->onRequest($this->requestEvent($session));
        }

        $this->clock->advance(3500);

        $this->expectException(AccessDeniedException::class);

        $listener->onRequest($this->requestEvent($session));
    }

    public function testUneSessionExpireeEstVideeEtLeJetonRetire(): void
    {
        $session = $this->openedSession();
        $this->clock->advance(3600);

        try {
            $this->listener()->onRequest($this->requestEvent($session));
            self::fail('La session aurait dû tomber.');
        } catch (AccessDeniedException) {
            self::assertNull($this->tokens->getToken());
            self::assertFalse($session->has(SessionLifetimeListener::SESSION_KEY));
        }
    }

    public function testUneSessionQueLaConnexionNAPasVueEstIgnoree(): void
    {
        $session = new Session(new MockArraySessionStorage());
        $session->start();

        $this->clock->advance(2592000);
        $this->listener()->onRequest($this->requestEvent($session));

        self::assertFalse($session->has(SessionLifetimeListener::SESSION_KEY));
    }

    /** Une personne peut écourter la sienne : la valeur rangée est la sienne, pas celle du plafond. */
    public function testLaPreferencePersonnelleEstCelleQuiEstRangee(): void
    {
        $session = $this->openedSession(['arnaud' => ['idle_timeout' => 300]]);

        self::assertSame(300, $session->get(SessionLifetimeListener::SESSION_KEY)['idle']);
    }

    /**
     * @param array<string, array<string, bool|int>> $preferences
     */
    private function openedSession(array $preferences = []): Session
    {
        $session = new Session(new MockArraySessionStorage());
        $session->start();

        $now = $this->clock->now()->getTimestamp();
        $decisions = $this->resolver($preferences)->decideFor('arnaud', 'ROLE_USER');

        // Ce que `onLogin()` écrit. La connexion elle-même demande un authentificateur et un
        // passeport : la reconstituer ici n'éprouverait que Symfony.
        $session->set(SessionLifetimeListener::SESSION_KEY, [
            'opened_at' => $now,
            'seen_at' => $now,
            'idle' => $decisions->seconds(Setting::IdleTimeout),
            'absolute' => $decisions->seconds(Setting::AbsoluteTimeout),
        ]);

        return $session;
    }

    /** @param array<string, array<string, bool|int>> $preferences */
    private function resolver(array $preferences = []): PolicyResolver
    {
        return new PolicyResolver(
            new Policy([
                new Rule(Setting::IdleTimeout, 3600, [Decider::User]),
                new Rule(Setting::AbsoluteTimeout, 28800),
            ]),
            null,
            new InMemoryUserPreferences($preferences),
        );
    }

    private function listener(): SessionLifetimeListener
    {
        return new SessionLifetimeListener(
            $this->resolver(),
            $this->tokens,
            $this->clock,
            new Perimeter(['main']),
            new StubFirewall(),
        );
    }

    private function requestEvent(Session $session): RequestEvent
    {
        $request = Request::create('/une-page');
        $request->setSession($session);

        return new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
        );
    }
}
