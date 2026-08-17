<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web;

use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use ArnaudMoncondhuy\Authorization\Proof;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;
use Symfony\Component\HttpFoundation\Response;

/**
 * Une page qui demande au juge ce qu'elle a le droit de croire.
 *
 * La question ne se pose que dans une requête : c'est elle qui porte la session où vit la
 * fraîcheur, et le pare-feu qui situe l'appelant. L'interroger depuis un test sans requête
 * rendrait toujours la même réponse — celle d'un appelant que rien ne situe.
 */
#[DuringEnrollment('Elle ne fait que rapporter ce que le juge répond.')]
final readonly class ProofController
{
    public function __construct(private ProofOfIdentity $identity)
    {
    }

    public function __invoke(): Response
    {
        return new Response(\sprintf(
            'strong=%d recent=%d',
            (int) $this->identity->meets(Proof::Strong),
            (int) $this->identity->meets(Proof::Recent),
        ));
    }
}
