<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Oblivion;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Efface d'un compte tout ce que ce paquet range.
 *
 * Aucune clé étrangère ne peut faire ce travail : le paquet range sous l'identité que le jeton
 * porte, et ne connaît ni la table des comptes ni sa clé primaire. Ce qu'un compte a posé lui
 * survit donc, et un compte recréé sous la même identité en hériterait.
 *
 * Le cas d'usage de suppression de compte appelle {@see Oblivion} ; cette commande est là pour
 * la main humaine, et pour ce qui a déjà été supprimé sans elle.
 */
#[AsCommand(
    name: 'authentication-policy:forget',
    description: 'Efface les moyens d\'authentification rangés sous une identité.',
)]
final class ForgetCommand extends Command
{
    public function __construct(private readonly ?Oblivion $oblivion = null)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument(
            'identity',
            InputArgument::REQUIRED,
            'L\'identité sous laquelle le compte se connecte, telle que le jeton la porte.',
        );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $console = new SymfonyStyle($input, $output);

        if (null === $this->oblivion) {
            $console->error('Ce paquet ne range rien ici : aucun mécanisme n\'est allumé, ou aucun n\'emploie son rangement.');

            return Command::FAILURE;
        }

        $identity = (string) $input->getArgument('identity');
        $this->oblivion->forgetEverythingOf($identity);

        $console->success(\sprintf('Tout ce qui était rangé sous « %s » est effacé.', $identity));

        return Command::SUCCESS;
    }
}
