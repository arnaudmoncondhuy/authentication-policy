<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ProvenEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\Visitor;
use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\LastFactorRemoval;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

/**
 * L'écran des clés : les poser, les nommer, les retirer.
 *
 * Le défi d'enrôlement est fabriqué à l'affichage et rangé dans la session : le navigateur en a
 * besoin avant que quiconque ait cliqué, puisque c'est lui qui interroge l'appareil.
 */
#[DuringEnrollment('On y pose son premier moyen : le verrou doit laisser passer.')]
final readonly class SecurityKeyController
{
    public const string CSRF_TOKEN_ID = 'authentication_policy_security_key';

    public function __construct(
        private SecurityKey $securityKey,
        private Factors $factors,
        private ProvenEnrollment $enrollment,
        private Visitor $visitor,
        private Environment $twig,
        private UrlGeneratorInterface $urls,
        private ?CsrfTokenManagerInterface $csrf,
        private string $template,
        private ?string $layout,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $user = $this->visitor->identifier();

        if (!$request->isMethod('POST')) {
            return $this->render($request, $user);
        }

        $this->requireCsrf($request);

        $geste = $request->request->get('geste');

        // Poser ou retirer un moyen sur un compte qui en a déjà un demande une identité prouvée
        // récemment. Sans cela, une session dérobée s'équipe elle-même et se rend fraîche.
        if ('add' === $geste && !$this->enrollment->allowsAdding($user)) {
            return $this->reprove();
        }

        return match ($geste) {
            'add' => $this->add($request, $user),
            'remove' => $this->remove($request, $user),
            default => $this->back(),
        };
    }

    /**
     * Renvoie présenter un moyen, plutôt que de refuser sèchement : ce qui manque se répare en
     * une manipulation, et l'écran de redemande ramène ici une fois l'identité prouvée.
     */
    private function reprove(): RedirectResponse
    {
        try {
            return new RedirectResponse($this->urls->generate('authentication_policy_reprove'));
        } catch (\Throwable) {
            return $this->back();
        }
    }

    private function add(Request $request, string $user): Response
    {
        $posed = $this->securityKey->finishEnrolment(
            $user,
            (string) $request->request->get('nom'),
            (string) $request->request->get('reponse'),
            $request->getSession(),
            $request->getHost(),
        );

        return $posed
            ? $this->back()
            : $this->render($request, $user, 'Cette clé n’a pas pu être posée. Reprenez depuis le début.');
    }

    private function remove(Request $request, string $user): Response
    {
        // Le refus « c'est ton dernier moyen » l'emporte sur l'exigence de preuve : voir le
        // commentaire du même geste dans le mécanisme du code à usage unique.
        try {
            $this->factors->requireRemovable($user, 'security_key');
        } catch (LastFactorRemoval $refus) {
            return $this->render($request, $user, $refus->getMessage());
        }

        if (!$this->enrollment->allowsRemoving($user)) {
            return $this->reprove();
        }

        try {
            $this->securityKey->removeFor($user, (string) $request->request->get('cle'));
        } catch (LastFactorRemoval $refus) {
            return $this->render($request, $user, $refus->getMessage());
        }

        return $this->back();
    }

    private function render(Request $request, string $user, ?string $error = null): Response
    {
        $keys = $this->securityKey->keysOf($user);

        return new Response($this->twig->render($this->template, [
            'layout' => $this->layout,
            'cles' => $keys,
            'options' => $this->securityKey->beginEnrolment($user, $request->getSession()),
            'autres_moyens' => $this->factors->countFor($user) - \count($keys),
            'erreur' => $error,
            'csrf_token_id' => self::CSRF_TOKEN_ID,
        ]));
    }

    private function back(): RedirectResponse
    {
        return new RedirectResponse($this->urls->generate($this->securityKey->manageAt()));
    }

    private function requireCsrf(Request $request): void
    {
        if (null === $this->csrf) {
            return;
        }

        if (!$this->csrf->isTokenValid(new CsrfToken(self::CSRF_TOKEN_ID, (string) $request->request->get('_token')))) {
            throw new AccessDeniedException('Jeton de sécurité invalide.');
        }
    }
}
