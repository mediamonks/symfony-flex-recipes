<?php

namespace App\Console\Command;

use App\Entity\User;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Yaml\Yaml;

final class AdminSetupCommand extends Command
{
    const OPTION_FORCE_USER_CREATION = 'force-user-creation';

    const CHAR_LIST_URL_SAFE = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    const CHAR_LIST_PASSWORD = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+~';

    const LENGTH_ADMIN_DIRECTORY = 16;

    private InputInterface $input;

    private OutputInterface $output;

    private array $users = [];

    private bool $clearCache = false;

    public function __construct(private readonly EntityManagerInterface $entityManager, private readonly UserPasswordHasherInterface $passwordHasher)
    {
        parent::__construct();
    }

    protected function configure()
    {
        $this
            ->setName('admin:setup')
            ->setDescription('Setup Sonata Admin for first use')
            ->addOption(
                'force-user-creation',
                null,
                InputOption::VALUE_NONE,
                'Force users to be generated (will delete all users!)'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->input = $input;
        $this->output = $output;

        $this->assertDatabase();
        $this->assertSchema();
        $this->generateAdminPath();
        $this->updateSecurityConfiguration();
        $this->truncateUsers();
        $this->createAdminUser('root', ['ROLE_ROOT']);
        $this->createAdminUser('superAdmin', ['ROLE_SUPER_ADMIN']);
        $this->createAdminUser('admin', ['ROLE_ADMIN']);

        if ($this->clearCache) {
            $this->cacheClear();
        }

        $this->finish();

        return Command::SUCCESS;
    }

    /**
     * Make sure we have a clean cache
     */
    private function cacheClear()
    {
        $this->output->writeln(
            'A cache flush is required for changes to take effect.'
        );
        $command = $this->getApplication()->find('cache:clear');
        $command->run(new ArrayInput([]), $this->output);
    }

    /**
     * Output relevant information to the user
     */
    protected function finish()
    {
        if (count($this->users) > 0) {
            $this->output->writeln([
                '',
                '<comment>Store these generated users in a safe place (a private Assembla page for instance). These credentials will be outputted only once!</comment>',
                '',
            ]);
            $table = new Table($this->output);
            $table->setHeaders(['Username', 'Password', 'Roles'])->setRows($this->users);
            $table->render();

            $this->output->writeln(['', '']);
        } else {
            $this->output->writeln([
                '',
                '<info>No new users were generated.</info>',
                '',
            ]);
        }

        $this->output->writeln([sprintf('<info>Admin is setup successfully at path "/%s"!</info>', $this->getAdminPath()), '']);

    }

    /**
     * Make sure we have proper database connectivity
     */
    private function assertDatabase()
    {
        try {
            $this->getDatabaseConnection()->fetchAssociative('SHOW TABLES');
        } catch (\Exception $e) {
            $this->output->writeLn(
                '<error>Database is not configured yet, please do this first and then run this script again.</error>'
            );

            exit;
        }
    }

    /**
     * Make sure the schema was generated so we can store users
     */
    private function assertSchema()
    {
        try {
            $this->getDatabaseConnection()->fetchAssociative('SELECT * FROM users');
        } catch (\Exception $e) {
            $this->output->write(
                '<info>Schema was not created yet, doing it now.</info>'
            );

            $command = $this->getApplication()->find('doctrine:schema:update');
            $returnCode = $command->run(
                new ArrayInput(['--force' => true]),
                $this->output
            );
            if ($returnCode !== 0) {
                $this->output->writeLn(
                    '<error>Schema could not be generated, please fix errors that can be seen above.</error>'
                );
                exit;
            }
        }
    }

    /**
     * Implement security configuration
     */
    private function updateSecurityConfiguration()
    {
        $security = $this->getConfigPath() . 'packages/security.yaml';
        $securityAdmin = $this->getConfigPath() . 'packages/security_admin.yaml.dist';
        if (!file_exists($securityAdmin)) {
            return;
        }

        $this->output->writeln(
            [
                '<info>The admin needs to have security rules setup in order to function.</info>',
                '<info>Since Flex does not allow security to be changed these settings will collide with the existing settings.</info>',
                '<info>If you have not yet configured security yourself you can safely let this script override</info>',
                '<info>the settings needed for the admin otherwise you will need to manually get the settings</info>',
                '',
            ]
        );

        $helper = $this->getHelper('question');
        $question = new ConfirmationQuestion(
            '<question>Do you want to override security settings automatically?</question>', true
        );
        if (!$helper->ask($this->input, $this->output, $question)) {
            $this->output->writeLn(
                '<comment>Please look at the securty_admin.yaml.dist for manual setup, then, run this script again.</comment>'
            );
            exit;
        }

        // replace security configs
        unlink($security);
        rename($securityAdmin, $security);

        $this->clearCache = true;
    }

    private function truncateUsers()
    {
        if (!$this->input->getOption(self::OPTION_FORCE_USER_CREATION)) {
            return;
        }

        $helper = $this->getHelper('question');
        $question = new ConfirmationQuestion(
            '<question>This will delete all users from your database, do you want to continue?</question>', true
        );
        if ($helper->ask($this->input, $this->output, $question)) {
            $this->getDatabaseConnection()->executeQuery('TRUNCATE TABLE users');
            $message = 'Users were deleted';
        } else {
            $message = 'Users were not deleted';
        }

        $this->output->writeln(
            [
                sprintf('<info>%s</info>', $message),
                '',
            ]
        );
    }

    private function createAdminUser(string $username, array $roles)
    {
        // do not generate users with the same role if they already exist
        $user = $this->getDatabaseConnection()->fetchAssociative(
            'SELECT id FROM users WHERE username LIKE ?',
            [$username . '%']
        );
        if (!empty($user)) {
            return;
        }

        $password = self::generateRandomString(20, self::CHAR_LIST_PASSWORD);
        $username = $username . self::generateRandomString(
                10,
                self::CHAR_LIST_URL_SAFE
            );


        $user = new User;
        $user->setUsername($username);

        $user->setPassword($this->passwordHasher->hashPassword($user, $password));
        $user->setRoles($roles);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $this->users[] = [
            'username' => $username,
            'password' => $password,
            'roles' => implode(',', $roles),
        ];
    }

    private function generateAdminPath()
    {
        $file = $this->getServicesYamlPath();

        $contents = file_get_contents($file);
        $search = "admin_path: 'admin'";
        if (stripos($contents, $search) === false) {
            return;
        }

        file_put_contents(
            $file,
            str_replace(
                $search,
                sprintf(
                    "admin_path: 'admin_%s'",
                    $this->generateRandomString(
                        self::LENGTH_ADMIN_DIRECTORY,
                        self::CHAR_LIST_URL_SAFE
                    )
                ),
                $contents
            )
        );

        $this->clearCache = true;
    }

    private function getAdminPath(): string
    {
        $data = Yaml::parseFile($this->getServicesYamlPath());
        return $data['parameters']['admin_path'];
    }

    private function getServicesYamlPath(): string
    {
        return $this->getConfigPath() . 'services.yaml';
    }

    private function getDatabaseConnection(): Connection
    {
        return $this->entityManager->getConnection();
    }

    private function generateRandomString(int $length = 10, string $characters): string
    {
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[random_int(0, $charactersLength - 1)];
        }

        return $randomString;
    }

    private function getConfigPath(): string
    {
        return __DIR__ . '/../../../config/';
    }
}