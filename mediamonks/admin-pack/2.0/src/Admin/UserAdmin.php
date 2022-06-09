<?php

namespace App\Admin;

use App\Entity\User;
use Sonata\AdminBundle\Admin\AbstractAdmin;
use Sonata\AdminBundle\Datagrid\ListMapper;
use Sonata\AdminBundle\Form\FormMapper;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;
use Symfony\Component\Validator\Constraints\NotBlank;

class UserAdmin extends AbstractAdmin
{
    private UserPasswordHasherInterface $userPasswordHasher;
    private AuthorizationCheckerInterface $authorizationChecker;
    private RoleHierarchyInterface $roles;

    public function __construct(?string $code = null, ?string $class = null, ?string $baseControllerName = null, UserPasswordHasherInterface $userPasswordHasher, AuthorizationCheckerInterface $authorizationChecker, RoleHierarchyInterface $roles)
    {
        parent::__construct($code, $class, $baseControllerName);
        $this->userPasswordHasher = $userPasswordHasher;
        $this->authorizationChecker = $authorizationChecker;
        $this->roles = $roles;
    }

    /**
     * {@inheritdoc}
     */
    public function configureExportFields(): array
    {
        // avoid security field to be exported
        return array_filter(
            $this->getExportFields(),
            function ($v) {
                return !in_array($v, ['password', 'salt']);
            }
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function configureListFields(ListMapper $list): void
    {
        $list
            ->addIdentifier('username')
            ->add('createdAt')
        ;

        if ($this->authorizationChecker->isGranted('ROLE_ALLOWED_TO_SWITCH')) {
            $list
                ->add(
                    'impersonating',
                    'string',
                    ['template' => 'admin/security/impersonating.html.twig']
                );
        }

        $list->add(
            '_action',
            'actions',
            [
                'actions'  => [
                    'edit'   => ['template' => '@SonataAdmin/CRUD/list__action_edit.html.twig'],
                    'delete' => ['template' => '@SonataAdmin/CRUD/list__action_delete.html.twig']
                ],
                'template' => '@SonataAdmin/CRUD/list__action.html.twig'
            ]
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function configureFormFields(FormMapper $form): void
    {
        /** @var User $user */
        $user = $this->getSubject();
        $roles =$this->roles->getReachableRoleNames($user->getRoles());

        $passwordFieldOptions = ['required' => (!$user || is_null($user->getId()))];
        if ((!$this->getSubject() || is_null($user->getId()))) {
            $passwordFieldOptions['constraints'] = new NotBlank();
        }

        $form
            ->with('General')
            ->add('username')
            ->add(
                'plainPassword',
                TextType::class,
                $passwordFieldOptions
            )
            ->end();

        if ($this->authorizationChecker->isGranted('ROLE_ADMIN', $this->getSubject())) {
            $form
                ->with('Roles')
                ->add(
                    'roles',
                    ChoiceType::class,
                    [
                        'label' => false,
                        'expanded' => true,
                        'multiple' => true,
                        'required' => false,
                        'choices' => array_combine(array_keys($roles), array_keys($roles))
                    ]
                )
                ->end();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function preUpdate($object): void
    {
        $this->updatePassword();
    }

    /**
     * {@inheritdoc}
     */
    public function prePersist($object): void
    {
        $this->updatePassword();
    }

    private function updatePassword()
    {
        if ($this->getSubject()->getPlainPassword()) {
            /** @var User $user */
            $user = $this->getSubject();
            $this->getSubject()->updatePassword($this->userPasswordHasher->hashPassword($user, $this->getSubject()->getPlainPassword()));
        }
    }
}
