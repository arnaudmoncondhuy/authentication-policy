<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ExitDoor;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Environment;

/**
 * L'étape de connexion par une clé de sécurité.
 *
 * Le défi est fabriqué au moment de rendre le formulaire : le navigateur en a besoin avant que
 * quiconque ait cliqué, puisque c'est lui qui interroge l'appareil.
 */
final readonly class SecurityKeyAtLogin implements TwoFactorProviderInterface, TwoFactorFormRendererInterface
{
    public function __construct(
        private SecurityKey $securityKey,
        private Perimeter $perimeter,
        private ExitDoor $exit,
        private TokenStorageInterface $tokens,
        private RequestStack $requests,
        private Environment $twig,
        private string $template,
        private ?string $layout,
    ) {
    }

    public function beginAuthentication(AuthenticationContextInterface $context): bool
    {
        return $this->perimeter->covers($context->getFirewallName())
            && $this->securityKey->countFor($context->getUser()->getUserIdentifier()) > 0;
    }

    public function needsPreparation(): bool
    {
        return false;
    }

    public function prepareAuthentication(object $user): void
    {
    }

    public function validateAuthenticationCode(object $user, string $authenticationCode): bool
    {
        $request = $this->requests->getMainRequest();

        return $user instanceof UserInterface
            && null !== $request
            && $request->hasSession()
            && $this->securityKey->verify(
                $user->getUserIdentifier(),
                $authenticationCode,
                $request->getSession(),
                $request->getHost(),
            );
    }

    public function getFormRenderer(): TwoFactorFormRendererInterface
    {
        return $this;
    }

    public function renderForm(Request $request, array $templateVars): Response
    {
        $user = $this->tokens->getToken()?->getUserIdentifier();

        return new Response($this->twig->render($this->template, [
            ...$templateVars,
            'layout' => $this->layout,
            'sortie' => $this->exit->path(),
            'options' => null === $user || !$request->hasSession()
                ? null
                : $this->securityKey->beginChallenge($user, $request->getSession()),
            'cles' => null === $user ? [] : $this->securityKey->keysOf($user),
        ]));
    }
}
