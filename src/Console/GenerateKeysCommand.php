<?php
declare(strict_types=1);

namespace Konsela\Auth\Console;

use Illuminate\Console\Command;

/**
 * Command to generate RSA key pair for JWT signing.
 *
 * @author frada <fbahezna@gmail.com>
 */
class GenerateKeysCommand extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'konsela:generate-keys
                          {--force : Overwrite existing keys}
                          {--bits=4096 : Key size in bits (2048, 4096)}';

    /**
     * The console command description.
     */
    protected $description = 'Generate RSA key pair for JWT authentication';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $bits = (int) $this->option('bits');
        $force = $this->option('force');

        // Validate key size
        if (!in_array($bits, [2048, 4096], true)) {
            $this->error('Key size must be either 2048 or 4096 bits.');
            return self::FAILURE;
        }

        // Get paths from config
        $privateKeyPath = config('konsela.auth.jwt.private_key_path', storage_path('keys/private.pem'));
        $publicKeyPath = config('konsela.auth.jwt.public_key_path', storage_path('keys/public.pem'));

        // Check if keys already exist
        if (!$force && (file_exists($privateKeyPath) || file_exists($publicKeyPath))) {
            $this->warn('Keys already exist. Use --force to overwrite.');
            return self::FAILURE;
        }

        // Create directory if it doesn't exist
        $keyDir = dirname($privateKeyPath);
        if (!is_dir($keyDir)) {
            mkdir($keyDir, 0755, true);
            $this->info("Created directory: {$keyDir}");
        }

        try {
            // Generate private key
            $this->info("Generating {$bits}-bit RSA key pair...");

            $config = [
                'private_key_bits' => $bits,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ];

            $privateKey = openssl_pkey_new($config);

            if ($privateKey === false) {
                throw new \RuntimeException('Failed to generate private key: ' . openssl_error_string());
            }

            // Export private key
            openssl_pkey_export($privateKey, $privateKeyPem);
            file_put_contents($privateKeyPath, $privateKeyPem);
            chmod($privateKeyPath, 0600); // Restrict permissions

            $this->info("Private key saved to: {$privateKeyPath}");

            // Export public key
            $publicKeyDetails = openssl_pkey_get_details($privateKey);
            file_put_contents($publicKeyPath, $publicKeyDetails['key']);
            chmod($publicKeyPath, 0644);

            $this->info("Public key saved to: {$publicKeyPath}");

            $this->newLine();
            $this->info('✓ JWT keys generated successfully!');
            $this->newLine();

            // Security reminders
            $this->warn('SECURITY REMINDERS:');
            $this->line('1. Never commit private.pem to version control');
            $this->line('2. Ensure private.pem has permissions 600 (read/write owner only)');
            $this->line('3. Add *.pem to your .gitignore file');
            $this->line('4. Backup your keys securely');
            $this->newLine();

            // Update .env suggestion
            $this->info('Add these to your .env file:');
            $this->line("JWT_PRIVATE_KEY_PATH={$privateKeyPath}");
            $this->line("JWT_PUBLIC_KEY_PATH={$publicKeyPath}");

            return self::SUCCESS;

        } catch (\Exception $e) {
            $this->error('Failed to generate keys: ' . $e->getMessage());
            return self::FAILURE;
        }
    }
}
