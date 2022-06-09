<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
#[ORM\Table(name: 'users')]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'integer')]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    protected ?int $id;

    #[ORM\Column(type: 'string', length: 180, unique: true, nullable: true)]
    protected ?string $username;

    #[ORM\Column(type: 'string', nullable: true)]
    protected ?string $password;

    protected ?string $plainPassword;

    #[ORM\Column(type: 'datetime', nullable: true)]
    protected ?\DateTimeInterface $lastLogin;

    #[ORM\Column(type: 'string', nullable: true)]
    protected ?string $tokenVerifier;

    #[ORM\Column(type: 'array', nullable: true)]
    protected array $roles;

    public function __construct()
    {
        $this->updateTokenVerifier();
    }

    public function __toString()
    {
        return (string)$this->getUsername();
    }

    public function getId(): int
    {
        return $this->id;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getUserIdentifier(): string
    {
        return (string)$this->getId();
    }

    public function setUsername(string $username)
    {
        $this->username = $username;
    }

    public function getLastLogin(): \DateTimeInterface
    {
        return $this->lastLogin;
    }

    public function setLastLogin(\DateTime $lastLogin)
    {
        $this->lastLogin = $lastLogin;
    }

    public function getTokenVerifier(): int
    {
        return $this->tokenVerifier;
    }

    public function setTokenVerifier(int $tokenVerifier)
    {
        $this->tokenVerifier = $tokenVerifier;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function setRoles(array $roles)
    {
        $this->roles = $roles;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles);
    }

    public function getSalt()
    {
        return null;
    }

    public function eraseCredentials()
    {
        $this->plainPassword = null;
    }

    public function updateTokenVerifier()
    {
        $this->tokenVerifier = time();
    }

    public function setPassword(string $password)
    {
        $this->password = $password;
    }

    public function getPlainPassword(): ?string
    {
        return $this->plainPassword;
    }

    public function setPlainPassword(string $plainPassword)
    {
        $this->plainPassword = $plainPassword;
    }
}