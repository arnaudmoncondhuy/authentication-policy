<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\Authorization\InsufficientProof;
use ArnaudMoncondhuy\Authorization\Proof;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Transforme en détour ce que l'autorisation oppose faute de preuve.
 *
 * Le paquet voisin lève et ne sait pas où renvoyer : il ne connaît aucun écran, et c'est ce qui
 * lui permet de rester ignorant de l'authentification. Celui-ci sait, et c'est tout ce que fait
 * cette classe.
 *
 * Deux destinations, et elles ne réparent pas la même chose. Un compte sans aucun moyen est
 * envoyé les poser — lui redemander ce qu'il n'a pas le laisserait devant un écran vide. Un
 * compte équipé qui n'a rien présenté depuis trop longtemps est envoyé le représenter.
 *
 * Sans écouteur, l'exception remonte et la surface rend une erreur du serveur : elle ferme, elle
 * n'ouvre pas — mais elle ne sert plus, et c'est pour cela que ceci existe.
 */
final readonly class InsufficientProofListener
{
    public function __construct(
        private ProofOfIdentity $identity,
        private ReturnPath $returnPath,
        private UrlGeneratorInterface $urls,
        private ?string $enrollmentPath,
    ) {
    }

    public function __invoke(ExceptionEvent $event): void
    {
        if (!$event->getThrowable() instanceof InsufficientProof) {
            return;
        }

        $this->returnPath->remember($event->getRequest());

        // Ce qui manque décide d'où l'on va. La question est reposée plutôt que déduite du
        // niveau exigé : `Recent` peut échouer faute de fraîcheur comme faute de moyen, et les
        // deux ne se réparent pas au même endroit.
        $destination = $this->identity->meets(Proof::Strong)
            ? $this->urls->generate('authentication_policy_reprove')
            : ($this->enrollmentPath ?? '/');

        $event->setResponse(new RedirectResponse($destination));
    }
}
