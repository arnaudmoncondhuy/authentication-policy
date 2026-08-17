<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Ce qu'un compte possède pour prouver qui il est, tous mécanismes confondus.
 *
 * C'est le seul endroit où les moyens se comptent ensemble, et c'est ce qui permet au paquet de
 * refuser le retrait de trop : chaque mécanisme ne connaît que lui-même, et retirerait le
 * dernier sans le savoir.
 */
final readonly class Factors
{
    /**
     * @param iterable<Factor> $factors  les mécanismes installés, dans l'ordre où ils se sont déclarés
     * @param bool             $required la politique peut-elle exiger un second facteur de quelqu'un
     */
    public function __construct(
        private iterable $factors,
        private bool $required,
    ) {
    }

    /**
     * Le total des moyens posés sur ce compte.
     */
    public function countFor(string $userIdentifier): int
    {
        $total = 0;

        foreach ($this->factors as $factor) {
            $total += max(0, $factor->countFor($userIdentifier));
        }

        return $total;
    }

    /**
     * Le détail, mécanisme par mécanisme, pour les écrans qui listent ce qu'on a posé.
     *
     * @return array<non-empty-string,int>
     */
    public function detailFor(string $userIdentifier): array
    {
        $detail = [];

        foreach ($this->factors as $factor) {
            $detail[$factor->name()] = max(0, $factor->countFor($userIdentifier));
        }

        return $detail;
    }

    /**
     * Autorise, ou non, à retirer des exemplaires d'un moyen.
     *
     * Le compte est fait sur ce qui resterait, jamais sur ce qui existe : un mécanisme qui
     * demanderait s'il peut retirer ses deux derniers codes doit s'entendre répondre non, même
     * s'il en a deux au moment où il pose la question.
     *
     * @throws LastFactorRemoval si le compte se retrouverait sans rien
     */
    public function requireRemovable(string $userIdentifier, string $factorName, int $howMany = 1): void
    {
        if (!$this->required) {
            return;
        }

        if ($this->countFor($userIdentifier) - max(0, $howMany) <= 0) {
            throw LastFactorRemoval::of($factorName);
        }
    }
}
