<?php

namespace App\Command;

use Composer\Composer;
use Composer\IO\ConsoleIO;
use Composer\Package\Package;
use Defuse\Crypto\Key;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Flex\Configurator\ComposerScriptsConfigurator;
use Symfony\Flex\Configurator\EnvConfigurator;
use Symfony\Flex\Lock;
use Symfony\Flex\Options;
use Symfony\Flex\Recipe;

final class PiiSetupCommand extends Command
{
    public function __construct()
    {
        parent::__construct('pii:setup');
    }

    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     *
     * @return void
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $packageName = 'mediamonks/pii-pack';
        $lockFile = new Lock(__DIR__.'/../../symfony.lock');
        $package = new Package($packageName, '1.0', '1.0');
        $recipe = new Recipe($package, $packageName, '', []);
        $io = new ConsoleIO($input, $output, $this->getHelperSet());
        $composer = new Composer();
        $options = new Options();

        $envConfigurator = new EnvConfigurator($composer, $io, $options);
        $envConfigurator->configure($recipe, [
            'APP_ENCRYPTION_KEY' => (Key::createNewRandomKey())->saveToAsciiSafeString()
        ], $lockFile);
        $composerScriptsConfigurator = new ComposerScriptsConfigurator($composer, $io, $options);
        $composerScriptsConfigurator->unconfigure($recipe, [
            'pii:setup' => 'symfony-cmd'
        ], $lockFile);

        $services = __DIR__.'/../../config/packages/pii.yaml';
        file_put_contents($services, str_replace('#!', '', file_get_contents($services)));
    }
}
