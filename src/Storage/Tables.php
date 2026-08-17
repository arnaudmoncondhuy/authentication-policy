<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Storage;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Table;

/**
 * Les tables du paquet : leur nom, et leur venue au monde.
 *
 * Tout ce que le paquet range passe par ici. Le préfixe est commun, si bien qu'une application
 * exclut d'un seul motif les tables qu'aucune de ses entités ne décrit — sans quoi
 * `doctrine:migrations:diff` propose de les supprimer, ce qui ne se voit qu'en relisant la
 * migration produite.
 *
 * La création au premier usage est ce qui rend vraie la promesse « un fichier de configuration,
 * et le mécanisme est utilisable ». Elle se coupe pour les environnements où le compte de base
 * de données n'a pas à posséder le schéma : les tables sont alors tenues par les migrations du
 * projet, et {@see \ArnaudMoncondhuy\AuthenticationPolicy\Bridge\DoctorCommand} dit celles qui
 * manquent.
 */
final class Tables
{
    /**
     * Les tables déjà regardées, pour ne les regarder qu'une fois.
     *
     * @var array<string, true>
     */
    private array $checked = [];

    /** @param non-empty-string $prefix */
    public function __construct(
        private readonly Connection $connection,
        private readonly string $prefix,
        private readonly bool $autoSetup,
    ) {
    }

    public function connection(): Connection
    {
        return $this->connection;
    }

    /** @return non-empty-string */
    public function name(string $table): string
    {
        return $this->prefix.$table;
    }

    /**
     * Le nom de la table, créée si elle manque et qu'on a le droit de la créer.
     *
     * @param callable(Table): void $describe ce que la table contient, si elle est à créer
     *
     * @return non-empty-string
     */
    public function ready(string $table, callable $describe): string
    {
        $name = $this->name($table);

        if (isset($this->checked[$name]) || !$this->autoSetup) {
            return $name;
        }

        // La marque se pose avant la question : autrement, une base où la création échoue
        // ferait interroger le schéma à chaque requête.
        $this->checked[$name] = true;

        $schema = $this->connection->createSchemaManager();

        if ($schema->tablesExist([$name])) {
            return $name;
        }

        $definition = new Table($name);
        $describe($definition);
        $schema->createTable($definition);

        return $name;
    }

    /** Sans rien créer, quel que soit le réglage : ce qu'un diagnostic demande. */
    public function exists(string $table): bool
    {
        return $this->connection->createSchemaManager()->tablesExist([$this->name($table)]);
    }
}
