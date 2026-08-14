<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Fait tomber une session trop vieille, ou laissée sans activité.
 *
 * Deux durées, et deux fautes différentes : l'inactivité vise le poste qu'on a quitté sans
 * fermer, la durée absolue vise la session qui dure indéfiniment parce qu'on s'en sert tous les
 * jours. Aucune des deux ne remplace l'autre.
 *
 * Les deux durées sont résolues **à la connexion** et rangées dans la session. La politique
 * d'une session est donc celle du moment où elle s'est ouverte : c'est ce qui permet au
 * contrôle de chaque requête de ne lire que deux entiers, sans interroger ni base ni annuaire.
 * Une politique resserrée s'applique aux sessions ouvertes ensuite — les précédentes gardent la
 * leur jusqu'à leur terme, ce que la documentation dit et que `authentication-policy:doctor`
 * rappelle.
 *
 * L'expiration ne fabrique aucune redirection : elle vide la session, retire le jeton et refuse
 * l'accès. C'est le pare-feu de l'application qui décide alors où l'on va — sa page de
 * connexion, son point d'entrée à lui. Un paquet qui choisirait la destination imposerait sa
 * route à toutes les applications qui l'installent.
 */
final readonly class SessionLifetimeListener
{
    /**
     * La clé sous laquelle les deux durées et les deux repères vivent dans la session.
     *
     * Une seule entrée plutôt que quatre : ce qui s'écrit ensemble à la connexion se retire
     * ensemble, et une session qui n'a jamais vu la connexion n'en porte aucune trace partielle.
     */
    public const string SESSION_KEY = '_authentication_policy';

    public function __construct(
        private PolicyResolver $resolver,
        private TokenStorageInterface $tokens,
        private ClockInterface $clock,
    ) {
    }

    /**
     * À la connexion : résoudre une fois, et ranger.
     *
     * Une connexion sans session — un pare-feu de machines, une requête portant une clé — n'a
     * rien à ranger, et rien à faire tomber ensuite.
     */
    public function onLogin(LoginSuccessEvent $event): void
    {
        $request = $event->getRequest();

        if (!$request->hasSession()) {
            return;
        }

        $token = $event->getAuthenticatedToken();
        $decisions = $this->resolver->decideFor($token->getUserIdentifier(), ...$token->getRoleNames());
        $now = $this->clock->now()->getTimestamp();

        $request->getSession()->set(self::SESSION_KEY, [
            'opened_at' => $now,
            'seen_at' => $now,
            'idle' => $decisions->seconds(Setting::IdleTimeout),
            'absolute' => $decisions->seconds(Setting::AbsoluteTimeout),
        ]);
    }

    /**
     * À chaque requête : deux soustractions.
     *
     * **Le jeton se lit en premier, et cet ordre est le dispositif.** Un pare-feu paresseux —
     * `lazy: true`, celui de toutes les applications réelles — ne charge rien tant que personne
     * ne réclame le jeton : la session n'est alors pas démarrée, et un contrôle qui commencerait
     * par elle ne trouverait jamais rien à faire tomber. Il ne casserait pas ; il ne servirait à
     * rien, en silence.
     *
     * Le lire ne pose de cookie à personne : sans session précédente, le pare-feu n'ouvre rien
     * et rend un jeton nul. Un visiteur qui n'est pas connecté repart d'ici sans avoir été
     * touché.
     */
    public function onRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest() || null === $this->tokens->getToken()) {
            return;
        }

        $request = $event->getRequest();

        if (!$request->hasSession() || !$request->getSession()->isStarted()) {
            return;
        }

        $session = $request->getSession();
        $state = $session->get(self::SESSION_KEY);

        if (!\is_array($state)) {
            return;
        }

        /** @var array{opened_at: int, seen_at: int, idle: int, absolute: int} $state */
        $now = $this->clock->now()->getTimestamp();

        if ($now - $state['seen_at'] >= $state['idle']) {
            $this->close($session, 'Session close par inactivité.');
        }

        if ($now - $state['opened_at'] >= $state['absolute']) {
            $this->close($session, 'Session close : durée maximale atteinte.');
        }

        $state['seen_at'] = $now;
        $session->set(self::SESSION_KEY, $state);
    }

    /**
     * @throws AccessDeniedException toujours — c'est elle qui rend la main au pare-feu, lequel
     *                               renverra vers son propre point d'entrée
     */
    private function close(SessionInterface $session, string $reason): never
    {
        $session->invalidate();
        $this->tokens->setToken(null);

        throw new AccessDeniedException($reason);
    }
}
