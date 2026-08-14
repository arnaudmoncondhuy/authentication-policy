<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Une valeur stockée que la politique n'écoute pas, parce qu'elle ne délègue plus à ce niveau.
 *
 * Le cas naît d'un changement de configuration : un réglage ouvert à la personne, choisi par
 * elle, puis refermé. La valeur reste en base et n'a plus d'effet.
 *
 * Elle est écartée plutôt que refusée — refuser fermerait l'application à tous ceux qui ont
 * déjà choisi, sur un simple changement de fichier. Mais elle est rendue avec les décisions :
 * une valeur qu'on écarte sans le dire est une préférence que son propriétaire croit
 * appliquée.
 */
final readonly class IgnoredValue
{
    public function __construct(
        public Setting $setting,
        public Decider $from,
        public bool|int $value,
    ) {
    }

    public function explanation(): string
    {
        return \sprintf(
            'Le réglage « %s » est stocké pour %s, mais la politique ne lui délègue plus ce réglage.',
            $this->setting->value,
            $this->from->label(),
        );
    }
}
