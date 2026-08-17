<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\LastFactorRemoval;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

/**
 * L'écran des codes de secours : les poser, les lire une fois, les retirer.
 *
 * Les codes ne sont lisibles qu'au moment où ils viennent d'être posés, et ne repassent jamais
 * par la session ni par une redirection : quitter la page, c'est les avoir perdus. C'est ce qui
 * fait qu'on les note.
 */
final readonly class BackupCodesController
{
    public const string CSRF_TOKEN_ID = 'authentication_policy_backup_codes';

    public function __construct(
        private BackupCodes $backupCodes,
        private Factors $factors,
        private TokenStorageInterface $tokens,
        private Environment $twig,
        private UrlGeneratorInterface $urls,
        private ?CsrfTokenManagerInterface $csrf,
        private string $template,
        private ?string $layout,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $user = $this->currentUser();

        if (!$request->isMethod('POST')) {
            return $this->render(null);
        }

        $this->requireCsrf($request);

        if ('discard' === $request->request->get('geste')) {
            try {
                $this->backupCodes->discardFor($user);
            } catch (LastFactorRemoval $refus) {
                return $this->render(null, $refus->getMessage());
            }

            return new RedirectResponse($this->urls->generate('authentication_policy_backup_codes'));
        }

        return $this->render($this->backupCodes->generateFor($user));
    }

    /**
     * @param list<string>|null $codes ce qui vient d'être posé, et qui ne sera plus jamais lisible
     */
    private function render(?array $codes, ?string $error = null): Response
    {
        $user = $this->currentUser();

        return new Response($this->twig->render($this->template, [
            'layout' => $this->layout,
            'codes' => $codes,
            'restants' => $this->backupCodes->countFor($user),
            'autres_moyens' => $this->factors->countFor($user) - $this->backupCodes->countFor($user),
            'erreur' => $error,
            'csrf_token_id' => self::CSRF_TOKEN_ID,
        ]));
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

    private function currentUser(): string
    {
        $user = $this->tokens->getToken()?->getUserIdentifier();

        if (null === $user || '' === $user) {
            throw new AccessDeniedException('Les codes de secours appartiennent à un compte connecté.');
        }

        return $user;
    }
}
