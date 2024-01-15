using System;




//exp
abstract class Cipher
{
    public abstract byte[] Perform(byte[] input, byte[] key);
}


//----------------------------------------------------------------------------------------------------------------------
class Encryptor : Cipher
{
    public override byte[] Perform(byte[] input, byte[] key)
    {
        CipherUtils.Permutation(ref input, CipherUtils.IP);

        byte[] left = input[..4];
        byte[] right = input[4..];

  for (int i = 0; i < 16; i++)
        {
     byte[] expanded = CipherUtils.Expand(right);
     byte[] roundKey = CipherUtils.GenerateRoundKey(key, i);
            byte[] result = CipherUtils.XOR(expanded, roundKey);
            result = CipherUtils.Substitute(result);
          result = CipherUtils.Permute(result, CipherUtils.P);
          result = CipherUtils.XOR(left, result);

            left = right;
            right = result;
        }

        byte[] resultText = right.Concat(left).ToArray();
        CipherUtils.Permutation(ref resultText, CipherUtils.FP);

        return resultText;
    }
}

class Decryptor : Cipher
{
    public override byte[] Perform(byte[] input, byte[] key)
    {
        CipherUtils.Permutation(ref input, CipherUtils.IP);

        byte[] left = input[..4];
        byte[] right = input[4..];

        for (int i = 15; i >= 0; i--)
        {
            byte[] expanded = CipherUtils.Expand(left);
            byte[] roundKey = CipherUtils.GenerateRoundKey(key, i);
            byte[] result = CipherUtils.XOR(expanded, roundKey);
            result = CipherUtils.Substitute(result);
            result = CipherUtils.Permute(result, CipherUtils.P);
            result = CipherUtils.XOR(right, result);

            right = left;
            left = result;
        }

        byte[] resultText = left.Concat(right).ToArray();
        CipherUtils.Permutation(ref resultText, CipherUtils.FP);

        return resultText;
    }
}

static class CipherUtils
{
 public static readonly int[] IP = { 2, 6, 3, 1, 4, 8, 5, 7 };
 public static readonly int[] FP = { 4, 1, 3, 5, 7, 2, 8, 6 };
     public static readonly int[] E = { 4, 1, 2, 3, 2, 3, 4, 1 };
public static readonly int[] P = { 2, 4, 3, 1, 4, 3, 2, 1 };

    public static void Permutation(ref byte[] data, int[] table)
    {
        byte[] temp = new byte[table.Length];
        for (int i = 0; i < table.Length; i++)
        {
            temp[i] = data[table[i] - 1];
        }
        temp.CopyTo(data, 0);
    }

    public static byte[] XOR(byte[] a, byte[] b)
    {
        int length = Math.Min(a.Length, b.Length);
        byte[] result = new byte[length];

        for (int i = 0; i < length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }

        return result;
    }

    public static byte[] Expand(byte[] data)
    {
        byte[] result = new byte[E.Length];
        for (int i = 0; i < E.Length; i++)
        {
            result[i] = data[E[i] - 1];
        }
        return result;
    }

    public static byte[] Substitute(byte[] data)
    {
        byte[] result = new byte[data.Length / 2];

        for (int i = 0; i < data.Length; i += 2) {
            int row = (data[i] & 0xF0) >> 4;
            int col = i / 2;

            result[col] = S_BOXES[col, row];   }

        return result;
    }


    //----exp
    public static byte[] Permute(byte[] data, int[] table)
    {
        byte[] result = new byte[table.Length];
        for (int i = 0; i < table.Length; i++)
        {
            int index = table[i] - 1;
            if (index >= 0 && index < data.Length)
            {
                result[i] = data[index];
            }
            else
            {
                result[i] = 0;
            }
        }
        return result;
    }

    public static byte[] GenerateRoundKey(byte[] key, int round)
    {
        byte[] result = new byte[6];
        for (int i = 0; i < 6; i++)
        {  result[i] = key[(round * 6 + i) % key.Length]; }
        return result;
    }

    public static readonly byte[,] S_BOXES =
    {
     {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    };



    class EncryptDecryptProgram
    {
        static void Main()
        {
            string secretMessage = "HelloWord!!!";
            byte[] secretKey = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

            //------------------------------------------------------------------------------------------------------
            Console.WriteLine("Введий текст - " + secretMessage);
            byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(secretMessage);

            Decryptor decryptor = new Decryptor();
            byte[] encryptedMessage = decryptor.Perform(messageBytes, secretKey);

            Encryptor encryptor = new Encryptor();
            byte[] decryptedMessage = encryptor.Perform(encryptedMessage, secretKey);

            Console.WriteLine();
            Console.WriteLine("Декодований текст - " + System.Text.Encoding.UTF8.GetString(decryptedMessage));
        }
    }
}
