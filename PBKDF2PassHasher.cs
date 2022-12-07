using System.Security.Cryptography;

namespace PBKDF2PassHash
{
    internal class PBKDF2PassHasher
    {
        /*
         * PHC string format
         * $pbkdf2-<digest>$i=<iterations>$<salt>$<hash>
         * https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#upgrading-legacy-hashes
         * https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
         * https://github.com/simonepri/phc-pbkdf2
         */

        private const string _algorithm = "$pbkdf2";
        private static readonly HashAlgorithmName _digest = HashAlgorithmName.SHA256;
        private static readonly string _digestLower = HashAlgorithmName.SHA256.ToString().ToLowerInvariant();
        private static readonly string _algorithmDigest = string.Join('-', _algorithm, _digestLower);
        // Why 310,000 iterations?
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        private const int _iterations = 310_000;
        private const char _segmentDelimiter = '$';
        // Why use a 16 byte salt?
        // https://nakedsecurity.sophos.com/2022/11/30/serious-security-md5-considered-harmful-to-the-tune-of-600000/
        private const int _saltSize = 16; // 128 bits
        private const int _keySize = 32; // 256 bits

        public string Hash(string input)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(_saltSize);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                input,
                salt,
                _iterations,
                _digest,
                _keySize
            );

            return string.Join(
                _segmentDelimiter,
                _algorithmDigest,
                _iterations,
                Convert.ToBase64String(salt),
                Convert.ToBase64String(hash)
            );
        }

        public bool Verify(string input, string hashString)
        {
            string[] segments = hashString.Split(_segmentDelimiter);
            string algorithmDigest = segments[1];
            var digestType = algorithmDigest.Split('-')[1];
            int iterations = int.Parse(segments[2]);
            byte[] salt = Convert.FromBase64String(segments[3]);
            byte[] hash = Convert.FromBase64String(segments[4]);
            HashAlgorithmName digest = new(digestType.ToUpperInvariant());
            byte[] inputHash = Rfc2898DeriveBytes.Pbkdf2(
                input,
                salt,
                iterations,
                digest,
                hash.Length
            );

            return CryptographicOperations.FixedTimeEquals(inputHash, hash);
        }
    }
}
