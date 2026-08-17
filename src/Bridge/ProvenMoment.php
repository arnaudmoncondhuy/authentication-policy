<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Quand cette session a présenté un moyen pour la dernière fois.
 *
 * En session, et nulle part ailleurs. Une preuve n'appartient pas au compte mais à
 * l'ouverture : rangée en base, elle voyagerait d'un navigateur à l'autre, et prouver son
 * identité sur son téléphone dispenserait de la prouver sur l'ordinateur laissé au bureau —
 * exactement ce que la fraîcheur existe pour empêcher.
 *
 * Ce n'est pas un journal. Il n'y a qu'une date, la dernière, et elle disparaît avec la
 * session : savoir qui a prouvé quoi et quand, durablement, est un autre sujet.
 */
final readonly class ProvenMoment
{
    private const string KEY = 'authentication_policy.proven_at';

    public function __construct(
        private RequestStack $requests,
        private ClockInterface $clock,
    ) {
    }

    /** Marque l'instant présent comme celui où l'identité a été prouvée. */
    public function record(): void
    {
        $this->requests->getSession()->set(self::KEY, $this->clock->now()->getTimestamp());
    }

    /**
     * Depuis combien de secondes, ou nul si cette session n'a jamais rien présenté.
     *
     * Une horloge qui recule — un serveur remis à l'heure — rendrait un âge négatif ; il est
     * ramené à zéro, ce qui laisse passer plutôt que de redemander sans fin. La preuve a bien
     * eu lieu : c'est la mesure qui est fausse.
     */
    public function ageInSeconds(): ?int
    {
        $session = $this->requests->getSession();

        if (!$session->has(self::KEY)) {
            return null;
        }

        /** @var int $moment */
        $moment = $session->get(self::KEY);

        return max(0, $this->clock->now()->getTimestamp() - $moment);
    }

    /** Efface la marque : ce qui vient d'être présenté ne vaut plus pour ce qui suit. */
    public function forget(): void
    {
        $this->requests->getSession()->remove(self::KEY);
    }
}
