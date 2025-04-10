#include "rsa.h"
#include <bitset>
#include <string>
using namespace std;

namespace bitsetOperations
{
    bitset<numberSize> operator+(bitset<numberSize> a, bitset<numberSize> b);
    void operator++(bitset<numberSize>& num);
    void operator+=(bitset<numberSize>& a, bitset<numberSize> b);
    bitset<numberSize> operator-(bitset<numberSize> num);
    bitset<numberSize> operator-(bitset<numberSize> a, bitset<numberSize> b);
    void operator-=(bitset<numberSize>& a, bitset<numberSize> b);

    bitset<numberSize> operator*(bitset<numberSize> a, bitset<numberSize> b);
    void operator*=(bitset<numberSize>& a, bitset<numberSize> b);

    bitset<numberSize> operator/(bitset<numberSize> a, bitset<numberSize> b);
    void operator/=(bitset<numberSize>& a, bitset<numberSize> b);
    bitset<numberSize> operator%(bitset<numberSize> a, bitset<numberSize> b);
    void operator%=(bitset<numberSize>& a, bitset<numberSize> b);

    bool operator<(bitset<numberSize> a, bitset<numberSize> b);
    bool operator>(bitset<numberSize> a, bitset<numberSize> b);
    bool operator<=(bitset<numberSize> a, bitset<numberSize> b);
    bool operator>=(bitset<numberSize> a, bitset<numberSize> b);



    namespace helper
    {
        pair<bitset<numberSize>, bitset<numberSize>> div(bitset<numberSize> a, bitset<numberSize> b)
        {
            bitset<numberSize> remainder = 0, qoutient = 0;

            for (int i = numberSize - 1; i >= 0; i--)
            {
                remainder <<= 1;
                if (a[i]) remainder[0] = 1;

                if (remainder >= b)
                {
                    remainder -= b;
                    qoutient[i] = 1;
                }
            }

            return { qoutient, remainder };
        }
    }



    bitset<numberSize> operator+(bitset<numberSize> a, bitset<numberSize> b)
    {
        bitset<numberSize> ans = 0;
        bool carry = 0;
        for (int i = 0; i < numberSize; i++)
        {
            ans[i] = a[i] ^ b[i] ^ carry;
            carry = (a[i] & b[i]) | (carry & (a[i] | b[i]));
        }
        return ans;
    }
    void operator++(bitset<numberSize>& num)
    {
        num = num + bitset<numberSize>(1);
    }
    void operator+=(bitset<numberSize>& a, bitset<numberSize> b)
    {
        a = a + b;
    }
    bitset<numberSize> operator-(bitset<numberSize> num)
    {
        num = ~num;
        return num + bitset<numberSize>(1);
    }
    bitset<numberSize> operator-(bitset<numberSize> a, bitset<numberSize> b)
    {
        return a + (-b);
    }
    void operator-=(bitset<numberSize>& a, bitset<numberSize> b)
    {
        a = a - b;
    }




    bitset<numberSize> operator*(bitset<numberSize> a, bitset<numberSize> b)
    {
        bitset<numberSize> ans = 0;
        if (a.count() > b.count()) swap(a, b);
        for (int i = 0; i < numberSize; i++) if (a[i]) ans += (b << i);
        return ans;
    }
    void operator*=(bitset<numberSize>& a, bitset<numberSize> b)
    {
        a = a * b;
    }




    bitset<numberSize> operator/(bitset<numberSize> a, bitset<numberSize> b)
    {
        return helper::div(a, b).first;
    }
    void operator/=(bitset<numberSize>& a, bitset<numberSize> b)
    {
        a = a / b;
    }
    bitset<numberSize> operator%(bitset<numberSize> a, bitset<numberSize> b)
    {
        return helper::div(a, b).second;
    }
    void operator%=(bitset<numberSize>& a, bitset<numberSize> b)
    {
        a = a % b;
    }




    bool operator<(bitset<numberSize> a, bitset<numberSize> b)
    {
        if (a[numberSize - 1] ^ b[numberSize - 1]) return a[numberSize - 1];
        for (int i = numberSize - 2; i >= 0; i--) if (a[i] ^ b[i]) return b[i];
        return false;
    }

    bool operator>(bitset<numberSize> a, bitset<numberSize> b)
    {
        return !(a < b) && !(a == b);
    }

    bool operator<=(bitset<numberSize> a, bitset<numberSize> b)
    {
        return a < b || a == b;
    }

    bool operator>=(bitset<numberSize> a, bitset<numberSize> b)
    {
        return !(a < b);
    }
}
using namespace bitsetOperations;





struct rsa
{
    bitset<numberSize> n, pub, priv, xorKey;

    rsa(bitset<numberSize> N, bitset<numberSize> E, bitset<numberSize> D, bitset<numberSize> X) : n(N), pub(E), priv(D), xorKey(X)
    { }

    rsa(int N, int E, int D, int X): n(bitset<numberSize>(N)), pub(bitset<numberSize>(E)), priv(bitset<numberSize>(D)), xorKey(bitset<numberSize>(X))
    { }



    string encrypt(string msg)
    {
        string encrypted = "", temp;
        bitset<numberSize> chunk, key = xorKey;
        int ind;
        if (msg.size() % chunkSize != 0) msg += string(chunkSize - (msg.size() % chunkSize), 0);



        for (int i = 0; i < msg.size(); i += chunkSize)
        {
            ind = 0;
            chunk = 0;
            for (int j = 0; j < chunkSize; j++) for (int k = 0; k < 8; k++) chunk[ind++] = msg[i + j] & (1 << k);

            chunk = encryptChunk(chunk);
            chunk ^= key;
            ++key;

            ind = 0;
            temp = string(numberSize/8, 0);
            for (int j = 0; j < numberSize / 8; j++) for (int k = 0; k < 8; k++) if (chunk[j * 8 + k]) temp[j] ^= (1 << k);

            encrypted += temp;
        }

        return encrypted;
    }

    string decrypt(string msg)
    {
        string decrypted = "", temp;
        bitset<numberSize> chunk, key = xorKey;
        int ind;
        
        for (int i = 0; i < msg.size(); i += numberSize/8)
        {
            ind = 0;
            chunk = 0;
            for (int j = 0; j < numberSize / 8; j++) for (int k = 0; k < 8; k++) chunk[ind++] = msg[i + j] & (1 << k);

            chunk ^= key;
            ++key;
            chunk = decryptChunk(chunk);

            ind = 0;
            temp = string(chunkSize, 0);
            for (int j = 0; j < chunkSize; j++) for (int k = 0; k < 8; k++) if (chunk[ind++]) temp[j] ^= (1 << k);
            decrypted += temp;
        }

        while (!decrypted.empty() && decrypted.back() == 0) decrypted.pop_back();


        return decrypted;
    }



private:
    bitset<numberSize> pwr(bitset<numberSize>& a, bitset<numberSize>& b)
    {
        if (b.count() == 0) return bitset<numberSize>(1);
        bool tmp = b[0];
        b >>= 1;
        bitset<numberSize> temp = pwr(a, b);
        temp = (temp * temp) % n;
        if (tmp) temp = (temp * a) % n;
        return temp;
    }

    bitset<numberSize> encryptChunk(bitset<numberSize> msg)
    {
        bitset<numberSize> copy = pub;
        return pwr(msg, copy);
    }

    bitset<numberSize> decryptChunk(bitset<numberSize> msg)
    {
        bitset<numberSize> copy = priv;
        return pwr(msg, copy);
    }
};