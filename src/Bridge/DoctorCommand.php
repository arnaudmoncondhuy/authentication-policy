<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Decider;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Examine une installation, et dit ce que personne d'autre ne dira.
 *
 * Les passes de compilation tiennent ce qui est démontrable : une délégation sans stockage, un
 * verrou sans sortie, une durée sans plafond, un mécanisme que rien ne demande à la connexion.
 * Restent des choses qu'aucune d'elles ne peut refuser, parce qu'aucune n'est une faute — et
 * que toutes se paient plus tard.
 *
 * **Les durcissements sans bouton.** La limitation des tentatives et les attributs du cookie de
 * session n'appartiennent pas à ce paquet, ne cassent rien par leur absence, et ne s'écrivent
 * dans aucun journal. Ils s'oublient donc, et c'est ici qu'on les voit.
 *
 * **Les réglages que ce paquet résout sans les appliquer.** Une politique peut permettre un
 * appareil de confiance ; c'est le projet qui en tire les conséquences. La distinction est
 * invisible à la lecture de la configuration, et c'est exactement là qu'on croit tenu ce qui ne
 * l'est pas.
 *
 * **Les tables que personne n'a migrées.** Quand la création au premier usage est coupée, une
 * table oubliée ne se découvre qu'au premier compte qui essaie, et pour lui seul.
 *
 * Elle échoue plutôt que d'afficher : une routine qualité ne peut s'appuyer que sur ce qui rend
 * un code de sortie.
 */
#[AsCommand(
    name: 'authentication-policy:doctor',
    description: 'Vérifie qu\'une installation de la politique d\'authentification se tient.',
)]
final class DoctorCommand extends Command
{
    /**
     * @param list<string>                        $findings
     * @param list<string>                        $firewalls
     * @param array<string, array{enabled: bool}> $mechanisms
     */
    public function __construct(
        private readonly Policy $policy,
        private readonly array $findings = [],
        private readonly ?string $enrollmentPath = null,
        private readonly ?RolePolicies $roles = null,
        private readonly ?UserPreferences $preferences = null,
        private readonly array $firewalls = [],
        private readonly array $mechanisms = [],
        private readonly bool $autoSetup = true,
        private readonly ?ProofOfIdentity $judge = null,
        private readonly int $freshness = 0,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $console = new SymfonyStyle($input, $output);

        $this->reportThePerimeter($console);
        $this->reportTheMechanisms($console);
        $this->reportTheLock($console);
        $this->reportTheStores($console);
        $this->reportTheProofBridge($console);
        $this->reportWhoEnforces($console);

        return $this->reportHardenedDefaults($console);
    }

    private function reportThePerimeter(SymfonyStyle $console): void
    {
        $console->section('Le périmètre');

        $console->writeln([] === $this->firewalls
            ? 'Aucun pare-feu confié : ce paquet ne gouverne rien.'
            : 'Pare-feux gouvernés : '.implode(', ', $this->firewalls).'. Tout le reste lui échappe, par construction.');
    }

    private function reportTheMechanisms(SymfonyStyle $console): void
    {
        $console->section('Les moyens fabriqués');

        $enabled = $this->enabledMechanisms();

        if ([] === $enabled) {
            $console->writeln('Aucun. Personne ne peut poser de second facteur.');

            return;
        }

        $console->writeln('Allumés : '.implode(', ', $enabled).'.');
        $console->writeln($this->autoSetup
            ? 'Leurs tables se créent au premier usage.'
            : 'Leurs tables sont tenues par vos migrations : une table oubliée ne se verra qu\'au premier compte qui essaie.');
    }

    private function reportTheLock(SymfonyStyle $console): void
    {
        $console->section('Le verrou d\'enrôlement');

        if (!$this->policy->canRequire(Setting::TwoFactor)) {
            $console->writeln('Ouvert : la politique n\'exige de second facteur de personne, et ne le délègue pas.');

            return;
        }

        $console->writeln(\sprintf(
            'Fermé par défaut. Une porte non dispensée renvoie vers %s.',
            $this->enrollmentPath ?? '(aucun chemin)',
        ));
    }

    private function reportTheStores(SymfonyStyle $console): void
    {
        $console->section('Où les décisions déléguées sont rangées');

        $console->table(
            ['Niveau', 'Réglages délégués', 'Stockage branché'],
            [
                [
                    Decider::Role->label(),
                    self::names($this->policy->delegatedTo(Decider::Role)),
                    null === $this->roles ? 'aucun' : $this->roles::class,
                ],
                [
                    Decider::User->label(),
                    self::names($this->policy->delegatedTo(Decider::User)),
                    null === $this->preferences ? 'aucun' : $this->preferences::class,
                ],
            ],
        );
    }

    /**
     * Le pont vers le paquet d'autorisation : est-il monté, et à quelles conditions.
     *
     * N'échoue jamais. Ce qu'il rapporte n'est pas une faute mais une chose qu'aucune des deux
     * installations ne peut voir seule — le paquet d'à côté sait qu'un droit exige une preuve,
     * celui-ci sait s'il peut la donner, et personne ne réunit les deux.
     */
    private function reportTheProofBridge(SymfonyStyle $console): void
    {
        $console->section('Les actes qui redemandent l\'identité');

        if (null === $this->judge) {
            $console->writeln('Aucun : le paquet d\'autorisation n\'est pas là, ou aucun mécanisme n\'est allumé.');
            $console->writeln('Un droit qui exigerait une preuve arrêterait alors la compilation, de son côté.');

            return;
        }

        $console->writeln(\sprintf('Ce paquet répond au contrat %s.', ProofOfIdentity::class));
        $console->writeln(\sprintf('Une preuve reste récente %d secondes, puis se redemande.', $this->freshness));

        if (null === $this->enrollmentPath) {
            $console->writeln('');
            $console->writeln('⚠ Aucun chemin d\'enrôlement : un compte sans moyen devant un acte qui en exige un');
            $console->writeln('  serait renvoyé à la racine, sans savoir quoi faire. Poser `enrollment_path`.');

            return;
        }

        $console->writeln(\sprintf('Un compte sans moyen est renvoyé vers %s, un compte équipé vers l\'écran de redemande.', $this->enrollmentPath));
    }

    private function reportWhoEnforces(SymfonyStyle $console): void
    {
        $delegated = [];

        foreach (Setting::all() as $setting) {
            if (!$setting->enforcedHere() && $this->policy->canRequire($setting)) {
                $delegated[] = $setting->value;
            }
        }

        if ([] === $delegated) {
            return;
        }

        $console->section('Résolus ici, appliqués par vous');
        $console->writeln(
            "Ce paquet dit ce qui est exigé, il ne fabrique pas tout. Ces réglages n'ont d'effet\n"
            ."que si le code du projet les lit et en tire les conséquences :\n  - "
            .implode("\n  - ", $delegated)
        );
    }

    private function reportHardenedDefaults(SymfonyStyle $console): int
    {
        $console->section('Les durcissements que ce paquet ne règle pas');

        if ([] === $this->findings) {
            $console->success('Rien à signaler.');

            return Command::SUCCESS;
        }

        foreach ($this->findings as $finding) {
            $console->writeln(\sprintf('  - %s', $finding));
        }

        $console->error('Ces durcissements natifs manquent. Aucun ne casse quoi que ce soit par son absence.');

        return Command::FAILURE;
    }

    /** @return list<string> */
    private function enabledMechanisms(): array
    {
        $enabled = [];

        foreach ($this->mechanisms as $name => $mechanism) {
            if ($mechanism['enabled']) {
                $enabled[] = $name;
            }
        }

        return $enabled;
    }

    /** @param list<Setting> $settings */
    private static function names(array $settings): string
    {
        return [] === $settings
            ? 'aucun'
            : implode(', ', array_map(static fn (Setting $setting): string => $setting->value, $settings));
    }
}
