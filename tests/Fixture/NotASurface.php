<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;

/** Une dispense posée sur ce qu'aucune requête n'atteint : elle n'ouvre rien. */
#[DuringEnrollment('Une raison qui ne sauve rien : cette classe n\'est pas une porte.')]
final class NotASurface
{
}
