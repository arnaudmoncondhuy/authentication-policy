<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp;

use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\Writer\SvgWriter;

/**
 * L'adresse d'enrôlement, en image, quand de quoi la dessiner est installé.
 *
 * Facultatif à dessein : l'écran affiche sinon le secret en toutes lettres, ce qui marche
 * partout et se recopie à la main. Un paquet qui exigerait une bibliothèque d'image pour poser
 * un code à six chiffres serait un paquet qu'on n'allume pas.
 */
final readonly class QrCode
{
    /** @return string|null une image en ligne, ou nul si rien ne sait la dessiner */
    public function of(string $uri): ?string
    {
        if (!class_exists(Builder::class)) {
            return null;
        }

        // Un dessin vectoriel : il reste net quel que soit l'écran, et voyage dans la page
        // plutôt que dans une requête de plus.
        return (new Builder(writer: new SvgWriter(), data: $uri))->build()->getDataUri();
    }
}
