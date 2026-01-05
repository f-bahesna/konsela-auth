<?php
declare(strict_types=1);

namespace Konsela\Auth\Tests\Unit\Domain\Service;

use Konsela\Auth\Domain\Exception\ValidationException;
use Konsela\Auth\Domain\Service\CredentialsValidator;
use PHPUnit\Framework\TestCase;

class CredentialsValidatorTest extends TestCase
{
    private CredentialsValidator $validator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->validator = new CredentialsValidator(
            minPasswordLength: 8,
            maxUsernameLength: 255
        );
    }

    public function test_validates_correct_credentials(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->validate('john.doe', 'SecurePassword123!');
    }

    public function test_throws_exception_for_empty_username(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Username cannot be empty');

        $this->validator->validate('', 'SecurePassword123!');
    }

    public function test_throws_exception_for_empty_password(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Password cannot be empty');

        $this->validator->validate('john.doe', '');
    }

    public function test_throws_exception_for_short_password(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('at least 8 characters');

        $this->validator->validate('john.doe', 'short');
    }

    public function test_accepts_minimum_length_password(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->validate('john.doe', '12345678'); // Exactly 8 characters
    }

    public function test_throws_exception_for_username_exceeding_max_length(): void
    {
        $this->expectException(ValidationException::class);

        $longUsername = str_repeat('a', 256); // 256 characters
        $this->validator->validate($longUsername, 'SecurePassword123!');
    }

    public function test_custom_minimum_password_length(): void
    {
        $validator = new CredentialsValidator(minPasswordLength: 12);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('at least 12 characters');

        $validator->validate('john.doe', 'short'); // Less than 12 characters
    }

    public function test_validates_special_characters_in_username(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->validate('john.doe@example.com', 'SecurePassword123!');
    }

    public function test_validates_unicode_characters(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->validate('用户名', 'SecurePassword123!');
    }
}
