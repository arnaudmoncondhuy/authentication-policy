import { Controller } from '@hotwired/stimulus';

/*
 * Fait parler le navigateur à la clé de sécurité — clé USB, empreinte, reconnaissance de
 * l'appareil — puis renvoie sa réponse au serveur par le formulaire qui l'entoure.
 *
 * Le secret ne quitte jamais l'appareil : ce qui transite ici est une signature, valable pour
 * le seul défi qui vient d'être posé.
 *
 * Le bouton employé dit où chercher la clé : sur l'appareil lui-même, ou sur un objet à part.
 * Le navigateur s'en sert pour aller droit au bon écran — c'est une indication, jamais un
 * ordre : lui seul décide de ce qu'il propose au bout du compte.
 */
const HINTS = {
    device: ['client-device'],
    phone: ['hybrid'],
    portable: ['security-key'],
};

/*
 * Le navigateur ne mène qu'une demande à la fois : une seconde ferait échouer la première, et
 * la personne verrait un refus là où elle vient seulement de préciser son choix. Celle qui
 * était en cours est donc retirée avant que la nouvelle parte.
 *
 * Au niveau du module, et non de l'instance : deux écrans peuvent vivre dans la même page.
 */
let enCours = null;

export default class extends Controller {
    static values = { options: String, mode: String };
    static targets = ['answer', 'error'];

    connect() {
        if (!this.supported) {
            this.fail(this.element.dataset.securityKeyUnsupported);

            return;
        }

        // À la vérification, la demande part d'elle-même : la page n'a aucun moyen de savoir
        // si une clé est branchée, et une demande ouverte laisse l'appareil se manifester seul.
        // Poser la clé, en revanche, attend qu'on l'ait nommée.
        if (this.modeValue !== 'create') {
            this.sign();
        }
    }

    disconnect() {
        enCours?.abort();
        enCours = null;
    }

    async sign(event) {
        event?.preventDefault();

        if (!this.supported) {
            return;
        }

        // Une demande que personne n'a réclamée se retire sans rien dire : la personne n'a rien
        // tenté, et son écran n'a pas à se couvrir d'un échec.
        const spontanee = undefined === event;

        enCours?.abort();
        const abandon = new AbortController();
        enCours = abandon;

        // Les boutons ne se ferment que sur une demande réclamée : pendant une demande partie
        // seule, ils restent le moyen de dire « pas celle-là, celle-ci ».
        if (!spontanee) {
            this.busy(true);
        }

        try {
            const options = JSON.parse(this.optionsValue);
            const bouton = event?.submitter?.dataset ?? {};
            const wanted = bouton.securityKeyWanted;

            if (wanted === 'device') {
                options.hints = ['client-device'];
                options.authenticatorSelection = { ...options.authenticatorSelection, authenticatorAttachment: 'platform' };
            } else if (wanted === 'portable') {
                options.hints = ['security-key', 'hybrid'];
                options.authenticatorSelection = { ...options.authenticatorSelection, authenticatorAttachment: 'cross-platform' };
            }

            // Une clé désignée à l'écran : le navigateur n'a plus qu'elle à chercher, et sait
            // d'avance de quel côté regarder. C'est le seul moyen d'en viser une précisément —
            // les indications ne sont jamais qu'un conseil.
            if (bouton.securityKeyOnly !== undefined) {
                options.allowCredentials = [options.allowCredentials[Number(bouton.securityKeyOnly)]];
                options.hints = HINTS[bouton.securityKeyGenre] ?? [];
            } else if (spontanee) {
                // Personne n'a rien désigné : l'ordre des indications dit par où commencer, et
                // ce qu'on branche passe avant ce que le navigateur héberge lui-même.
                options.hints = this.preferences;
            }

            const credential =
                this.modeValue === 'create'
                    ? await navigator.credentials.create({
                          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
                          signal: abandon.signal,
                      })
                    : await navigator.credentials.get({
                          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
                          signal: abandon.signal,
                      });

            enCours = null;
            this.answerTarget.value = JSON.stringify(credential.toJSON());
            this.element.submit();
        } catch (refusal) {
            this.busy(false);

            // Une demande retirée pour laisser place à la suivante n'est pas un échec.
            if (!spontanee && 'AbortError' !== refusal.name) {
                this.fail(this.element.dataset.securityKeyRefused);
            }
        }
    }

    /*
     * Les genres de clés du compte, remis dans l'ordre où il vaut mieux les chercher.
     */
    get preferences() {
        const genres = [...this.element.querySelectorAll('[data-security-key-genre]')].map((b) => b.dataset.securityKeyGenre);

        return ['portable', 'phone', 'device'].filter((genre) => genres.includes(genre)).flatMap((genre) => HINTS[genre]);
    }

    get supported() {
        return (
            window.PublicKeyCredential !== undefined &&
            typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function'
        );
    }

    busy(state) {
        this.element.querySelectorAll('button[type="submit"]').forEach((button) => {
            button.disabled = state;
        });
    }

    /*
     * L'encadré ne prend son habillage qu'en portant un message : la classe qui le dessine
     * impose un affichage, et le laisser habillé d'avance le rendrait visible et vide.
     */
    fail(message) {
        if (!this.hasErrorTarget || !message) {
            return;
        }

        this.errorTarget.textContent = message;
        this.errorTarget.className = 'app-alert';
        this.errorTarget.dataset.tone = 'danger';
        this.errorTarget.hidden = false;
    }
}
