//%block="RSA"
//%color="#f5718b"
//%icon="\uf3ed"
namespace rsa {
    /**
     * Generate prime numbers within a range.
     */
    //%blockid=rsa_primegen
    //%block="generate prime number array"
    //%group="key id"
    //%weight=10
    export function generatePrimes(limit: number): number[] {
        const primes: number[] = [];
        for (let i = 2; i <= limit; i++) {
            if (isPrime(i)) primes.push(i);
        }
        return primes;
    }

    /**
     * Check if a number is prime.
     */
    function isPrime(num: number): boolean {
        if (num < 2) return false;
        for (let i = 2, sqrt = Math.sqrt(num); i <= sqrt; i++) {
            if (num % i === 0) return false;
        }
        return true;
    }

    /**
     * Calculate the greatest common divisor (GCD).
     */
    function gcd(a: number, b: number): number {
        return b === 0 ? a : gcd(b, a % b);
    }

    /**
     * Generate RSA keys (public and private).
     */
    //%blockid=rsa_genkey
    //%block="generate rsa as dual key"
    //%blockSetVariable="myRsaKey"
    //%group="key id"
    //%weight=8
    export function generateKeys(): {publicKey: [number,number],privateKey: [number,number]} {
        const primes = generatePrimes(100);
        const p = primes[Math.floor(Math.random() * primes.length)];
        const q = primes[Math.floor(Math.random() * primes.length)];

        const n = p * q;
        const phi = (p - 1) * (q - 1);

        let e = 3;
        while (gcd(e, phi) !== 1) {
            e++;
        }

        let d = 1;
        while ((d * e) % phi !== 1) {
            d++;
        }

        return {publicKey: [e, n],privateKey: [d, n]};
    }

    export enum keyType {publicKey = 1,privateKey = 2}

    //%blockid=rsa_getkeyintype
    //%block="get $idkv from rsa key in $keyMode"
    //%idkv.shadow=variables_get idkv.defl="myRsaKey"
    //%group="key id"
    //%weight=6
    export function getRsaKey(idkv: {publicKey: [number,number], privateKey: [number,number]}, keyMode:keyType) {
        switch (keyMode) {
            case 1:
            return idkv.publicKey;
            case 2:
            return idkv.privateKey;
            default:
            return [-1,-1]
        }
    }

    /**
     * Encrypt a message using the public key.
     */
    //%blockid=rsa_keyandencode
    //%block="get $message to encode with publicKey: $publicKey"
    //%publicKey.shadow=variables_get publicKey.defl=myRsaPublicKey
    //%group="encoding and decoding"
    //%weight=10
    export function encrypt(message: string, publicKey: number[] ): number[] {
        if (publicKey.length !== 2) return [];
        const [e, n] = publicKey;
        return message.split('').map(char => {
            const m = char.charCodeAt(0);
            return modExp(m, e, n);
        });
    }

    /**
     * Decrypt a message using the private key.
     */
    //%blockid=rsa_keyanddecode
    //%block="get $cipher to decode with privateKey: $privateKey"
    //%privateKey.shadow=variables_get privateKey.defl=myRsaPrivateKey
    //%group="encoding and decoding"
    //%weight=8
    export function decrypt(cipher: number[], privateKey: number[]): string {
        if (privateKey.length !== 2) return "";
        const [d, n] = privateKey;
        return cipher.map(c => {
            const m = modExp(c, d, n);
            return String.fromCharCode(m);
        }).join('');
    }

    /**
     * Modular exponentiation (base^exp % mod).
     */
    function modExp(base: number, exp: number, mod: number): number {
        let result = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 === 1) {
                result = (result * base) % mod;
            }
            exp = Math.floor(exp / 2);
            base = (base * base) % mod;
        }
        return result;
    }
}
