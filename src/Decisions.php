<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Toute la politique appliquée à une personne, réglage par réglage.
 *
 * L'ensemble est complet : chaque cas de {@see Setting} y figure, y compris ceux dont la
 * configuration ne dit rien. Un écran qui parcourt cet objet ne peut donc pas oublier un
 * réglage — il apparaît, avec sa valeur la plus permissive et son auteur.
 */
final readonly class Decisions
{
    /** @var array<string, Decision> */
    private array $byId;

    /**
     * @param iterable<Decision> $decisions
     * @param list<IgnoredValue> $ignored   ce qui était stocké et que la politique n'écoute pas
     */
    public function __construct(iterable $decisions, private array $ignored = [])
    {
        $byId = [];

        foreach ($decisions as $decision) {
            $byId[$decision->setting->value] = $decision;
        }

        $this->byId = $byId;
    }

    public function of(Setting $setting): Decision
    {
        return $this->byId[$setting->value] ?? throw new UnknownSetting(\sprintf('Aucune décision pour le réglage « %s ». L\'ensemble n\'a pas été construit par PolicyResolver.', $setting->value));
    }

    /** @return list<Decision> */
    public function all(): array
    {
        return array_map($this->of(...), Setting::all());
    }

    /**
     * Ce qui était stocké pour cette personne et que la politique n'écoute plus.
     *
     * Vide dans le cas courant. Non vide, c'est un écran de profil qui doit dire « ce choix
     * ne s'applique plus », plutôt que de l'afficher comme s'il portait encore.
     *
     * @return list<IgnoredValue>
     */
    public function ignored(): array
    {
        return $this->ignored;
    }

    /** Le raccourci qu'emploie le verrou d'enrôlement, et qu'un projet emploiera pour ses propres mécanismes. */
    public function requires(Setting $setting): bool
    {
        return $this->of($setting)->requires();
    }

    public function allows(Setting $setting): bool
    {
        return $this->of($setting)->allows();
    }

    public function seconds(Setting $setting): int
    {
        return $this->of($setting)->seconds();
    }
}
