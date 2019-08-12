namespace Crypto.AES.Math
{
    public class PeasantMultiplication
    {
        public static int Calculate(int a, int b)
        {
            int aa = a, bb = b, r = 0, t;
            while (aa != 0)
            {
                if ((aa & 1) != 0)
                    r ^= bb;
                t = bb & 0x80;
                bb <<= 1;
                if (t != 0)
                    bb ^= 0x1b;
                aa >>= 1;
            }
            return r;
        }
    }
}
