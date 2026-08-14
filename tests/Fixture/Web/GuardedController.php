<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web;

use Symfony\Component\HttpFoundation\Response;

/** Une page ordinaire : rien n'y est déclaré, et c'est le verrou qui la ferme. */
final class GuardedController
{
    public function __invoke(): Response
    {
        return new Response('la page ordinaire');
    }
}
