# Ce qui reste au projet

Le paquet livre le mécanisme, jamais les garanties d'ensemble. Ce qui suit ne peut pas voyager,
vous appartient, et **rien du paquet ne vous préviendra**.

Chaque projet qui monte le paquet reverse ici la règle qu'il a enfreinte. C'est la seule chose
qui transforme un paquet correct en paquet qui prévient.

**1. `Enrollment::isCompleteFor()` est le point le plus sensible du dispositif.** Le verrou
entier tient à cette réponse. Une implémentation qui rendrait vrai par facilité — parce que la
colonne n'existe pas encore, parce qu'on teste — ouvre tout, et rien ne le signale.
*Vérifiable :* la méthode interroge un état persistant, jamais une constante ni une propriété
non renseignée.

**2. Un réglage résolu ici n'est pas un réglage appliqué.** `backup_codes`, `trusted_device` et
`remember_me` sont décidés par la politique et appliqués par vous. Une configuration qui les
exige sans que votre code les lise donne une politique qui a l'air tenue.
*Vérifiable :* `authentication-policy:doctor` les liste ; chacun a un appel correspondant dans
le projet.

**3. Les durées de session sont celles du moment de la connexion.** Elles sont résolues à
l'ouverture et rangées dans la session. Resserrer la politique ne raccourcit pas les sessions
déjà ouvertes — elles gardent la leur jusqu'à leur terme.
*Vérifiable :* un durcissement urgent s'accompagne d'une invalidation des sessions en cours, que
le paquet ne fait pas.

**4. L'expiration des clés de service n'est pas couverte.** Le paquet ne connaît que des comptes
qui ouvrent une session. Une clé posée dans un script y reste valable jusqu'à ce qu'on la
retire, et personne ne le rappellera.
*Vérifiable :* le gestionnaire de jetons du projet porte une échéance et un horodatage de
dernier usage.

**5. Le journal des connexions et la liste des sessions actives vous appartiennent.** Savoir
d'où l'on s'est connecté, couper une session oubliée sur un portable volé : rien de cela n'est
ici, et rien ne le remplace.

**6. L'aspiration de masse n'est pas de l'authentification.** Une identité légitime qui extrait
cent mille dossiers passe tous les contrôles de ce paquet. Le plafonnement de lecture est un
autre dispositif, et son absence ne se voit que dans les journaux.

**7. Renommer un cas de `Setting` casse les lignes déjà écrites.** L'identité voyage en base,
dans les préférences d'une personne et les réglages d'un rôle. La résolution refuse bruyamment
plutôt que d'écarter en silence — c'est le comportement voulu, mais la reprise des données est à
vous.
*Vérifiable :* toute montée de version qui touche l'énumération s'accompagne d'une migration.

**8. Une passe de compilation ne voit que des services.** Une dispense posée sur une classe
qu'aucun service ne désigne échappe au contrôle. Elle n'est alors atteinte par aucune requête,
donc n'ouvre rien — mais elle laisse croire le contraire à qui la lit.

**9. Le paquet ne décide pas qui a le droit de changer un réglage.** L'écran qui pose une
politique de rôle est une surface comme une autre : c'est de l'autorisation, et elle est
entièrement à vous.
*Vérifiable :* la page d'administration des politiques traverse un contrôle de droit.

**10. Le mécanisme lui-même reste à installer.** Le paquet dit que le second facteur est exigé ;
c'est `scheb/2fa-bundle` qui le demande, et votre pare-feu qui le pose. Une politique qui exige
sans mécanisme installé verrouille l'application sur une page d'enrôlement qui n'enrôle rien.
*Vérifiable :* le chemin d'enrôlement rend un écran qui écrit vraiment dans le stockage que
`Enrollment` relit.
