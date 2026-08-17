<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes;

use ArnaudMoncondhuy\AuthenticationPolicy\Challenge;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\LastFactorRemoval;

/**
 * Les codes de secours : le moyen d'entrer quand on a perdu tous les autres.
 *
 * Ils s'écrivent sur un papier, pas dans un gestionnaire de mots de passe rangé sur l'appareil
 * qu'on vient justement de perdre. Un code ne sert qu'une fois, et l'application ne le revoit
 * jamais en clair : seule son empreinte est gardée, comme un mot de passe.
 *
 * Les poser une seconde fois périme les précédents. C'est voulu : une série imprimée dont on ne
 * sait plus si elle est encore valable ne rassure personne.
 */
final readonly class BackupCodes implements Challenge
{
    public const string NAME = 'backup_codes';

    /** Assez de codes pour tenir, assez peu pour tenir sur un papier. */
    public const int HOW_MANY = 10;

    /**
     * Huit octets tirés au sort, soit de quoi rendre vaine la recherche exhaustive le jour où
     * la base fuite : les empreintes seules ne se remontent pas en codes.
     */
    public const int BYTES = 8;

    public function __construct(
        private BackupCodeStore $store,
        private Factors $factors,
        private int $howMany = self::HOW_MANY,
        private int $bytes = self::BYTES,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function countFor(string $userIdentifier): int
    {
        return \count($this->store->hashesFor($userIdentifier));
    }

    public function manageAt(): string
    {
        return 'authentication_policy_backup_codes';
    }

    public function isRecovery(): bool
    {
        return true;
    }

    /**
     * Pose une série neuve et la rend en clair — la seule et unique fois où elle est lisible.
     *
     * @return list<string> à montrer à la personne, jamais à ranger ailleurs
     */
    public function generateFor(string $userIdentifier): array
    {
        $codes = [];
        $hashes = [];

        for ($i = 0; $i < max(1, $this->howMany); ++$i) {
            $code = strtolower(bin2hex(random_bytes(max(4, $this->bytes))));
            // Recopié à la main depuis un papier : des groupes courts se relisent sans se perdre.
            $codes[] = implode('-', str_split($code, 4));
            $hashes[] = $this->hash($code);
        }

        $this->store->replaceAll($userIdentifier, $hashes);

        return $codes;
    }

    /**
     * Consomme un code s'il en existe un qui corresponde, et dit s'il en existait un.
     *
     * La comparaison passe par toutes les empreintes même après avoir trouvé : le temps de
     * réponse ne dit alors rien sur la position du code dans la liste.
     */
    public function consume(string $userIdentifier, string $code): bool
    {
        $proposed = $this->hash($this->normalize($code));
        $found = null;

        foreach ($this->store->hashesFor($userIdentifier) as $hash) {
            if (hash_equals($hash, $proposed)) {
                $found = $hash;
            }
        }

        if (null === $found) {
            return false;
        }

        $this->store->forget($userIdentifier, $found);

        return true;
    }

    /** Rien à présenter : le code est sur le papier qu'on a gardé, et un champ suffit. */
    public function question(string $userIdentifier): ?string
    {
        return null;
    }

    /**
     * Redemander consomme le code, comme à l'entrée.
     *
     * C'est voulu : un code qui servirait deux fois cesserait d'être à usage unique du seul
     * fait qu'on le présente ailleurs qu'à la connexion.
     */
    public function accepts(string $userIdentifier, string $answer): bool
    {
        return $this->consume($userIdentifier, $answer);
    }

    /**
     * Retire toute la série.
     *
     * @throws LastFactorRemoval si le compte n'a rien d'autre pour se connecter
     */
    public function discardFor(string $userIdentifier): void
    {
        $this->factors->requireRemovable($userIdentifier, $this->name(), $this->countFor($userIdentifier));

        $this->store->replaceAll($userIdentifier, []);
    }

    /**
     * Ce qui est saisi vient d'un papier recopié à la main : les espaces, les tirets et la
     * casse sont du bruit, et refuser un code juste pour un tiret n'apporte aucune sécurité.
     */
    private function normalize(string $code): string
    {
        return strtolower((string) preg_replace('/[^a-zA-Z0-9]/', '', $code));
    }

    private function hash(string $code): string
    {
        return hash('sha256', $code);
    }
}
