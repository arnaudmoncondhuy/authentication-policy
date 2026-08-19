<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

/**
 * Combien de fois on a le droit d'essayer devant un moyen.
 *
 * Le pare-feu de Symfony limite les tentatives sur le formulaire de connexion, et sur lui seul.
 * Les écrans de ce paquet acceptent pourtant un secret eux aussi — un code à six chiffres qui
 * vit trente secondes, un code de secours. Sans plafond, la parallélisation suffit : à cinquante
 * requêtes simultanées, l'espace d'un code à six chiffres se couvre en moins d'une heure, et
 * c'est précisément la porte qu'emprunte une session dérobée pour se refaire une fraîcheur.
 *
 * Chaque essai coûte un jeton, et une réussite les rend tous : se tromper deux fois dans la
 * journée ne doit enfermer personne dehors, et qui sait répondre ne doit rien payer.
 *
 * Le plafond porte sur l'identité, jamais sur l'adresse. Une adresse se change ; c'est ce
 * compte-là qu'on essaie d'ouvrir.
 */
final readonly class AttemptLimiter
{
    public function __construct(
        private RateLimiterFactoryInterface $limiters,
    ) {
    }

    /**
     * Prend un jeton pour cet essai.
     *
     * @return int|null null quand l'essai est permis, sinon le nombre de secondes à patienter.
     *                  Se lit avant de juger la réponse : ce qui n'est pas permis n'est pas jugé.
     */
    public function attempt(string $userIdentifier): ?int
    {
        $limit = $this->limiters->create($userIdentifier)->consume();

        if ($limit->isAccepted()) {
            return null;
        }

        return max(1, $limit->getRetryAfter()->getTimestamp() - time());
    }

    /**
     * La bonne réponse : le compte repart avec tous ses jetons.
     */
    public function forget(string $userIdentifier): void
    {
        $this->limiters->create($userIdentifier)->reset();
    }
}
