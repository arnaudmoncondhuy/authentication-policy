<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Decider;
use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

/**
 * L'écran « Ma sécurité » : tout ce qui protège le compte au même endroit.
 *
 * Les moyens de prouver qui l'on est, et la durée pendant laquelle on reste connecté. Les deux
 * sont décidés par la politique, et n'avaient jusqu'ici aucun endroit commun où se lire : chaque
 * application en dressait un, et personne n'y voyait le rapport.
 *
 * Aucun mécanisme n'est nommé : l'écran affiche ce que les moyens installés déclarent.
 */
#[DuringEnrollment('C\'est la page qui mène aux moyens : le verrou doit la laisser passer.')]
final readonly class SecurityScreenController
{
    public const string CSRF_TOKEN_ID = 'authentication_policy_security';

    /** Les durées d'inactivité proposées, en secondes. Celles qui dépassent le plafond tombent. */
    private const array PROPOSED_TIMEOUTS = [900, 3600, 7200, 28800];

    public function __construct(
        private Factors $factors,
        private PolicyResolver $resolver,
        private Policy $policy,
        private RolePolicies $roles,
        private ?UserPreferences $preferences,
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
        $roles = $this->visitor->roles();

        if ($request->isMethod('POST')) {
            return $this->remember($request, $user);
        }

        $decisions = $this->resolver->decideFor($user, ...$roles);
        $inventory = $this->factors->inventoryFor($user);

        // Sans les préférences : c'est le plafond que la personne peut encore resserrer, et il
        // ne doit pas rétrécir à mesure qu'elle choisit.
        $ceiling = (new PolicyResolver($this->policy, $this->roles))
            ->decideFor($user, ...$roles)
            ->seconds(Setting::IdleTimeout);

        // Le stockage des préférences n'existe que si la politique délègue quelque chose à
        // chacun. Sans lui, l'écran montre ce qui est décidé, sans rien proposer de choisir.
        $chosen = $this->preferences?->valuesFor($user) ?? [];

        return new Response($this->twig->render($this->template, [
            'layout' => $this->layout,
            'poses' => array_values(array_filter($inventory, static fn (array $factor): bool => $factor['count'] > 0)),
            'a_poser' => array_values(array_filter($inventory, static fn (array $factor): bool => 0 === $factor['count'])),
            'total' => $this->factors->countFor($user),
            'recours' => $this->factors->hasRecoveryFor($user),
            'inactivite' => $decisions->seconds(Setting::IdleTimeout),
            'duree_maximale' => $decisions->seconds(Setting::AbsoluteTimeout),
            'impose_par_role' => Decider::Role === $decisions->of(Setting::IdleTimeout)->decidedBy,
            'reglable' => null !== $this->preferences
                && $this->policy->ruleFor(Setting::IdleTimeout)->delegatesTo(Decider::User),
            'choix_possibles' => array_values(array_filter(
                self::PROPOSED_TIMEOUTS,
                static fn (int $seconds): bool => $seconds <= $ceiling,
            )),
            'choix_personnel' => $chosen[Setting::IdleTimeout->value] ?? null,
            'csrf_token_id' => self::CSRF_TOKEN_ID,
        ]));
    }

    /**
     * Retient le choix, sans rien vérifier de plus : ce qui dépasserait le plafond est ramené à
     * la résolution, et refuser ici obligerait à redemander son choix à quelqu'un le jour où la
     * politique se desserre.
     */
    private function remember(Request $request, string $user): Response
    {
        if (null !== $this->csrf
            && !$this->csrf->isTokenValid(new CsrfToken(self::CSRF_TOKEN_ID, (string) $request->request->get('_token')))) {
            throw new AccessDeniedException('Jeton de sécurité invalide.');
        }

        if (null === $this->preferences) {
            throw new AccessDeniedException('Aucune préférence ne se règle ici : la politique ne délègue rien.');
        }

        $chosen = (string) $request->request->get(Setting::IdleTimeout->value);

        $this->preferences->remember($user, [
            Setting::IdleTimeout->value => '' === $chosen ? null : max(60, (int) $chosen),
        ]);

        return new RedirectResponse($this->urls->generate('authentication_policy_security'));
    }
}
