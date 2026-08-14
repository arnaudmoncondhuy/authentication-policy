<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web;

use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use Symfony\Component\HttpFoundation\Response;

/** La page qui enrôle : elle doit rester joignable, et le dit. */
#[DuringEnrollment('Pose le second facteur : la verrouiller enfermerait tout le monde dehors.')]
final class EnrollmentController
{
    public function __invoke(): Response
    {
        return new Response('la page qui enrôle');
    }
}
