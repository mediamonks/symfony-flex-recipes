<?php

namespace App\Admin;

use Sonata\AdminBundle\Admin\AbstractAdmin;
use Sonata\AdminBundle\Datagrid\ListMapper;
use Sonata\AdminBundle\Form\FormMapper;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Security\Core\Tests\Encoder\PasswordEncoder;
use Symfony\Component\Validator\Constraints\NotBlank;

class UserAdmin extends AbstractAdmin
{
    /**
     * {@inheritdoc}
     */
    public function getExportFields()
    {
        // avoid security field to be exported
        return array_filter(
            parent::getExportFields(),
            function ($v) {
                return !in_array($v, ['password', 'salt']);
            }
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function configureListFields(ListMapper $listMapper)
    {
        $listMapper
            ->addIdentifier('username')
            ->add('createdAt')
        ;

        $securityChecker = $this->getConfigurationPool()->getContainer()->get('security.authorization_checker');

        if ($securityChecker->isGranted('ROLE_ALLOWED_TO_SWITCH')) {
            $listMapper
                ->add(
                    'impersonating',
                    'string',
                    ['template' => 'admin/security/impersonating.html.twig']
                );
        }

        $listMapper->add(
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
    protected function configureFormFields(FormMapper $formMapper)
    {
        $securityChecker = $this->getConfigurationPool()->getContainer()->get('security.authorization_checker');
        $roles = $this->getConfigurationPool()->getContainer()->getParameter('security.role_hierarchy.roles');

        $passwordFieldOptions = ['required' => (!$this->getSubject() || is_null($this->getSubject()->getId()))];
        if ((!$this->getSubject() || is_null($this->getSubject()->getId()))) {
            $passwordFieldOptions['constraints'] = new NotBlank();
        }

        $formMapper
            ->with('General')
            ->add('username')
            ->add(
                'plainPassword',
                TextType::class,
                $passwordFieldOptions
            )
            ->end();

        if ($securityChecker->isGranted('ROLE_ADMIN')) {
            $formMapper
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
    public function preUpdate($user)
    {
        $this->updatePassword();
    }

    /**
     * {@inheritdoc}
     */
    public function prePersist($user)
    {
        $this->updatePassword();
    }

    private function updatePassword()
    {
        /** @var PasswordEncoder $passwordEncoder */
        $passwordEncoder = $this->getConfigurationPool()->getContainer()->get('security.password_encoder');

        if ($this->getSubject()->getPlainPassword()) {
            $this->getSubject()->updatePassword($passwordEncoder->encodePassword($this->getSubject(), $this->getSubject()->getPlainPassword()));
        }
    }
}
