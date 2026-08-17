<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey;

/**
 * Ce qu'est une clé, du point de vue de la personne qui la range.
 *
 * L'appareil déclare par quels moyens il sait se faire reconnaître ; c'est de là que le genre
 * se déduit. Un appareil qui ne déclare rien reste indéterminé plutôt que mal rangé.
 */
enum Kind: string
{
    /** L'appareil lui-même : empreinte, visage, ou code de déverrouillage. */
    case Device = 'device';

    /** Un téléphone approché, qui répond pour un autre appareil. */
    case Phone = 'phone';

    /** Une clé qu'on transporte : prise USB, sans contact, ondes courtes. */
    case Portable = 'portable';

    case Unknown = 'unknown';

    /** @param list<string> $transports ce que l'appareil déclare savoir faire */
    public static function fromTransports(array $transports): self
    {
        return match (true) {
            \in_array('internal', $transports, true) => self::Device,
            \in_array('hybrid', $transports, true) => self::Phone,
            [] !== array_intersect(['usb', 'nfc', 'ble'], $transports) => self::Portable,
            default => self::Unknown,
        };
    }
}
