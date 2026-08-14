<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Decisions;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * La politique appliquée à qui est connecté maintenant.
 *
 * C'est ce qu'un écran de profil injecte : il en tire les valeurs, l'auteur de chacune et le
 * verrou, et n'a rien à recalculer. Le résolveur, lui, reste joignable directement pour tout ce
 * qui n'a pas de requête — une commande, un test, une tâche planifiée.
 *
 * L'identité et les rôles viennent du jeton de sécurité, jamais de la requête. C'est la seule
 * façon d'écrire ce service : les lire ailleurs offrirait au client le droit de désigner
 * quelqu'un d'autre, et donc de choisir la politique qu'on lui applique.
 */
final readonly class CurrentDecisions
{
    public function __construct(
        private PolicyResolver $resolver,
        private TokenStorageInterface $tokens,
    ) {
    }

    /**
     * @throws \LogicException si personne n'est connecté — un écran de profil n'existe pas sans
     *                         compte, et rendre la politique d'un inconnu n'aurait pas de sens
     */
    public function all(): Decisions
    {
        $token = $this->tokens->getToken();

        if (null === $token) {
            throw new \LogicException('Aucun compte connecté : appeler PolicyResolver directement avec une identité.');
        }

        return $this->resolver->decideFor($token->getUserIdentifier(), ...$token->getRoleNames());
    }
}
