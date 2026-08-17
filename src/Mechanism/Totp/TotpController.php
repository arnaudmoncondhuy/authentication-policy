<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp;

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
 * L'écran du code à six chiffres : le poser, le confirmer, le retirer.
 *
 * Poser un secret est une écriture, et n'arrive donc jamais en affichant la page : sans cela,
 * revenir sur l'écran périmerait le QR code qu'on est en train de photographier.
 */
#[DuringEnrollment('On y pose son premier moyen : le verrou doit laisser passer.')]
final readonly class TotpController
{
    public const string CSRF_TOKEN_ID = 'authentication_policy_totp';

    public function __construct(
        private Totp $totp,
        private Factors $factors,
        private QrCode $qrCode,
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
            return $this->render($user);
        }

        $this->requireCsrf($request);

        return match ($request->request->get('geste')) {
            'start' => $this->start($user),
            'confirm' => $this->confirm($user, (string) $request->request->get('code')),
            'forget' => $this->forget($user),
            default => $this->back(),
        };
    }

    /**
     * Poser puis renvoyer vers l'écran : l'adresse à photographier se reconstruit à
     * l'affichage, et rafraîchir la page ne pose pas un second secret.
     */
    private function start(string $user): Response
    {
        $this->totp->startFor($user);

        return $this->back();
    }

    private function confirm(string $user, string $code): Response
    {
        if ($this->totp->confirmFor($user, $code)) {
            return $this->back();
        }

        // Le secret en attente reste posé : refaire un QR code obligerait à recommencer toute
        // la manipulation pour un chiffre mal recopié.
        return $this->render($user, error: 'Ce code ne correspond pas. Vérifiez l’heure de votre appareil, puis réessayez.');
    }

    private function forget(string $user): Response
    {
        try {
            $this->totp->forgetFor($user);
        } catch (LastFactorRemoval $refus) {
            return $this->render($user, error: $refus->getMessage());
        }

        return $this->back();
    }

    private function render(string $user, ?string $error = null): Response
    {
        // Un secret posé mais jamais confirmé se reprend là où on l'a laissé : celui que
        // l'appareil a déjà lu est le bon, et en fabriquer un autre obligerait à recommencer.
        $uri = $this->totp->enrolmentUriFor($user);
        $posed = $this->totp->countFor($user) > 0;

        return new Response($this->twig->render($this->template, [
            'layout' => $this->layout,
            'pose' => $posed,
            'en_attente' => null !== $uri,
            'adresse' => $uri,
            'image' => null === $uri ? null : $this->qrCode->of($uri),
            'secret' => null === $uri ? null : $this->totp->secretFor($user),
            'autres_moyens' => $this->factors->countFor($user) - $this->totp->countFor($user),
            'erreur' => $error,
            'csrf_token_id' => self::CSRF_TOKEN_ID,
        ]));
    }

    private function back(): RedirectResponse
    {
        return new RedirectResponse($this->urls->generate($this->totp->manageAt()));
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
