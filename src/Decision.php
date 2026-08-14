<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Ce qu'un réglage vaut pour quelqu'un, et pourquoi.
 *
 * Les trois informations voyagent ensemble parce qu'un écran a besoin des trois : la valeur
 * pour l'afficher, l'auteur pour l'expliquer, le verrou pour savoir s'il propose un champ ou
 * une ligne de texte. Rendre la valeur seule oblige l'écran à redevenir la politique.
 */
final readonly class Decision
{
    public function __construct(
        public Setting $setting,
        public bool|int $value,
        public Decider $decidedBy,
        public bool $locked,
    ) {
    }

    /**
     * Vrai quand ce réglage est une exigence, et qu'elle porte.
     *
     * Le raccourci de lecture pour un mécanisme : c'est ce que le verrou d'enrôlement demande
     * de {@see Setting::TwoFactor}, et ce qu'un projet demande des réglages qu'il applique
     * lui-même.
     */
    public function requires(): bool
    {
        return Kind::Requirement === $this->setting->kind() && true === $this->value;
    }

    public function allows(): bool
    {
        return Kind::Permission === $this->setting->kind() && true === $this->value;
    }

    /**
     * Le nombre de secondes, pour un réglage de durée.
     *
     * @throws InvalidSettingValue si le réglage n'est pas une durée
     */
    public function seconds(): int
    {
        if (Kind::Duration !== $this->setting->kind() || !\is_int($this->value)) {
            throw new InvalidSettingValue(\sprintf('Le réglage « %s » n\'est pas une durée.', $this->setting->value));
        }

        return $this->value;
    }

    /** La phrase que l'écran de profil montre à la place d'un champ grisé sans explication. */
    public function explanation(): string
    {
        return $this->locked
            ? \sprintf('Imposé par %s.', $this->decidedBy->label())
            : \sprintf('Décidé par %s, et vous pouvez encore resserrer.', $this->decidedBy->label());
    }
}
