<?php

namespace App\Command;

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
use Symfony\Component\Security\Core\Encoder\BCryptPasswordEncoder;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Yaml\Yaml;

final class AdminConfigureCommand extends Command
{
    const NAME = 'admin:configure';

    const OPTION_FORCE_USER_CREATION = 'force-user-creation';

    const CHAR_LIST_URL_SAFE = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    const CHAR_LIST_PASSWORD = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+~';

    const LENGTH_SECRET = 40;

    const LENGTH_ADMIN_DIRECTORY = 16;

    const BCRYPT_COST = 13;

    /**
     * @var EntityManagerInterface
     */
    private $entityManager;

    /**
     * @var InputInterface
     */
    private $input;

    /**
     * @var OutputInterface
     */
    private $output;

    /**
     * @var array
     */
    private $users = [];

    /**
     * @var bool
     */
    private $clearCache = false;

    /**
     * @param EntityManagerInterface $entityManager
     */
    public function __construct(EntityManagerInterface $entityManager)
    {
        $this->entityManager = $entityManager;

        parent::__construct();
    }

    /**
     *
     */
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

    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     *
     * @return void
     */
    protected function execute(InputInterface $input, OutputInterface $output)
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
        }
        else {
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
            $this->getDatabaseConnection()->fetchAssoc('SHOW TABLES');
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
            $this->getDatabaseConnection()->fetchAssoc('SELECT * FROM users');
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
        $security = $this->getConfigPath().'packages/security.yaml';
        $securityAdmin = $this->getConfigPath().'packages/security_admin.yaml.dist';
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
            $this->getDatabaseConnection()->exec('TRUNCATE TABLE users');
            $message = 'Users were deleted';
        }
        else {
            $message = 'Users were not deleted';
        }

        $this->output->writeln(
            [
                sprintf('<info>%s</info>', $message),
                '',
            ]
        );
    }

    /**
     * Generate a new admin user
     *
     * @param string $username
     * @param array $roles
     */
    private function createAdminUser($username, array $roles)
    {
        // do not generate users with the same role if they already exist
        $user = $this->getDatabaseConnection()->fetchAssoc(
            'SELECT id FROM users WHERE username LIKE ?',
            [$username.'%']
        );
        if (!empty($user)) {
            return;
        }

        $password = self::generateRandomString(20, self::CHAR_LIST_PASSWORD);
        $username = $username.self::generateRandomString(
                10,
                self::CHAR_LIST_URL_SAFE
            );


        $user = new User;
        $user->setUsername($username);

        $user->setPassword($this->getPasswordEncoder()->encodePassword($password, null));
        $user->setRoles($roles);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $this->users[] = [
            'username' => $username,
            'password' => $password,
            'roles' => implode(',', $roles)
        ];
    }

    /**
     * @return BCryptPasswordEncoder
     */
    private function getPasswordEncoder()
    {
        $data = Yaml::parseFile($this->getSecurityYamlPath());
        if (!isset($data['security']['encoders'][UserInterface::class]['algorithm'])) {
            $this->output->writeln('<error>Security file was not updated correctly.</error>');
            exit;
        }
        $encoder = $data['security']['encoders'][UserInterface::class]['algorithm'];
        if ($encoder !== 'bcrypt') {
            $this->output->writeln('<error>This script only works with bcrypt for now.</error>');
            exit;
        }

        return new BCryptPasswordEncoder(self::BCRYPT_COST);
    }

    /**
     * Generate a random admin path
     */
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

    /**
     * @return string
     */
    private function getAdminPath()
    {
        $data = Yaml::parseFile($this->getServicesYamlPath());
        return $data['parameters']['admin_path'];
    }

    /**
     * @return string
     */
    private function getServicesYamlPath()
    {
        return $this->getConfigPath().'services.yaml';
    }

    /**
     * @return string
     */
    private function getSecurityYamlPath()
    {
        return $this->getConfigPath().'packages/security.yaml';
    }

    /**
     * @return Connection
     */
    private function getDatabaseConnection()
    {
        return $this->entityManager->getConnection();
    }

    /**
     * @param int $length
     * @param $characters
     *
     * @return string
     */
    private function generateRandomString($length = 10, $characters)
    {
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[random_int(0, $charactersLength - 1)];
        }

        return $randomString;
    }

    /**
     * @return string
     */
    private function getConfigPath()
    {
        return __DIR__.'/../../config/';
    }
}
