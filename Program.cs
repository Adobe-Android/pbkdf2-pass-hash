namespace PBKDF2PassHash
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var passHasher = new PBKDF2PassHasher();
            string password = "password";

            // Hash:
            string hashed = passHasher.Hash(password);
            Console.WriteLine(hashed);

            // Verify:
            bool isPasswordCorrect = passHasher.Verify(password, hashed);
            Console.WriteLine(isPasswordCorrect);
        }
    }
}