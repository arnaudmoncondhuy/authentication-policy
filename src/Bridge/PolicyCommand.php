<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Decider;
use ArnaudMoncondhuy\AuthenticationPolicy\Kind;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\Rule;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Affiche la politique telle qu'elle s'applique, et non telle qu'on croit l'avoir écrite.
 *
 * Sans elle, savoir ce qu'un rôle subit demande de lire un fichier de configuration, une table
 * de rôles, et de replier les deux de tête. C'est faisable une fois ; ça ne se refait pas à
 * chaque revue, et c'est ainsi qu'une politique cesse d'être connue de ceux qui la portent.
 *
 * Avec `--role`, elle rejoue la résolution pour les rôles nommés — sans les préférences de qui
 * que ce soit, qui appartiennent à une personne et non à un rôle.
 */
#[AsCommand(
    name: 'authentication-policy:policy',
    description: 'Affiche la politique d\'authentification, et ce qu\'elle donne pour des rôles.',
)]
final class PolicyCommand extends Command
{
    public function __construct(
        private readonly Policy $policy,
        private readonly ?RolePolicies $roles = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption(
            'role',
            null,
            InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
            'Rejoue la résolution pour ces rôles, tels que le jeton les porte (ROLE_ADMIN…).',
        );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $console = new SymfonyStyle($input, $output);

        $console->section('Ce que la configuration déclare');
        $console->table(
            ['Réglage', 'Nature', 'Plafond', 'Délégué à', 'Appliqué par'],
            array_map(self::declaredRow(...), $this->policy->all()),
        );

        /** @var list<string> $roles */
        $roles = $input->getOption('role');

        if ([] === $roles) {
            $console->writeln('Ajouter --role=ROLE_ADMIN pour voir ce que la politique donne à un rôle.');

            return Command::SUCCESS;
        }

        $console->section(\sprintf('Ce que reçoit un compte portant %s', implode(' + ', $roles)));

        // Sans les préférences : elles appartiennent à une personne, et la commande ne parle que
        // de rôles. Les inclure demanderait une identité, et rendrait le résultat inexact pour
        // tous les autres comptes du même rôle.
        $decisions = (new PolicyResolver($this->policy, $this->roles))->decideFor('', ...$roles);

        $console->table(
            ['Réglage', 'Valeur', 'Décidé par', 'Encore modifiable par la personne'],
            array_map(
                static fn ($decision): array => [
                    $decision->setting->value,
                    self::humanValue($decision->setting->kind(), $decision->value),
                    $decision->decidedBy->label(),
                    $decision->locked ? 'non' : 'oui',
                ],
                $decisions->all(),
            ),
        );

        $console->writeln('Les préférences personnelles ne peuvent que resserrer ces valeurs.');

        return Command::SUCCESS;
    }

    /** @return list<string> */
    private static function declaredRow(Rule $rule): array
    {
        $delegated = array_map(
            static fn (Decider $decider): string => $decider->label(),
            $rule->delegatedTo,
        );

        return [
            $rule->setting->value,
            self::humanKind($rule->setting->kind()),
            self::humanValue($rule->setting->kind(), $rule->ceiling),
            [] === $delegated ? 'personne' : implode(', ', $delegated),
            $rule->setting->enforcedHere() ? 'ce paquet' : 'le projet',
        ];
    }

    private static function humanKind(Kind $kind): string
    {
        return match ($kind) {
            Kind::Requirement => 'exigence',
            Kind::Permission => 'permission',
            Kind::Duration => 'durée',
        };
    }

    private static function humanValue(Kind $kind, bool|int $value): string
    {
        if (Kind::Duration === $kind && \is_int($value)) {
            return \PHP_INT_MAX === $value ? 'aucune limite' : self::humanDuration($value);
        }

        return match ($kind) {
            Kind::Requirement => true === $value ? 'exigé' : 'non exigé',
            default => true === $value ? 'autorisé' : 'interdit',
        };
    }

    private static function humanDuration(int $seconds): string
    {
        return match (true) {
            $seconds >= 86400 => \sprintf('%s j', round($seconds / 86400, 1)),
            $seconds >= 3600 => \sprintf('%s h', round($seconds / 3600, 1)),
            $seconds >= 60 => \sprintf('%s min', round($seconds / 60)),
            default => \sprintf('%d s', $seconds),
        };
    }
}
