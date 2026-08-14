<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web;

use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use Symfony\Component\HttpFoundation\Response;

/** Une porte dont une seule route s'ouvre pendant l'enrôlement. */
final class ExemptedMethodController
{
    #[DuringEnrollment('Rend les codes de secours, qu\'il faut avoir avant de pouvoir entrer.')]
    public function backupCodes(): Response
    {
        return new Response('les codes de secours');
    }

    public function settings(): Response
    {
        return new Response('les réglages');
    }
}
