#include <bitset>
#include <string>
#include <vector>
#include <iostream>
const int numberSize = 512;
const int chunkSize = 5;
using namespace std;

namespace bitsetOperations
{
    bitset<numberSize> operator+(bitset<numberSize> a, bitset<numberSize> b);
    void operator+=(bitset<numberSize> &a, bitset<numberSize> b);
    bitset<numberSize> operator-(bitset<numberSize> num);
    bitset<numberSize> operator-(bitset<numberSize> a, bitset<numberSize> b);
    void operator-=(bitset<numberSize> &a, bitset<numberSize> b);

    bitset<numberSize> operator*(bitset<numberSize> a, bitset<numberSize> b);
    void operator*=(bitset<numberSize> &a, bitset<numberSize> b);

    bitset<numberSize> operator/(bitset<numberSize> a, bitset<numberSize> b);
    void operator/=(bitset<numberSize> &a, bitset<numberSize> b);
    bitset<numberSize> operator%(bitset<numberSize> a, bitset<numberSize> b);
    void operator%=(bitset<numberSize> &a, bitset<numberSize> b);

    void operator%=(bitset<numberSize> &a, bitset<numberSize> b);
    bool operator<(bitset<numberSize> a, bitset<numberSize> b);
    bool operator>(bitset<numberSize> a, bitset<numberSize> b);
    bool operator<=(bitset<numberSize> a, bitset<numberSize> b);
    bool operator>=(bitset<numberSize> a, bitset<numberSize> b);



    namespace helper
    {
        pair<bitset<numberSize>, bitset<numberSize>> div(bitset<numberSize> a, bitset<numberSize> b)
        {
            bitset<numberSize> remainder = 0, qoutient = 0;

            for (int i = numberSize-1; i >= 0; i--)
            {
                remainder <<= 1;
                if (a[i]) remainder[0] = 1;

                if (remainder >= b)
                {
                    remainder -= b;
                    qoutient[i] = 1;
                }
            }

            return {qoutient, remainder};
        }
    }



    bitset<numberSize> operator+(bitset<numberSize> a, bitset<numberSize> b)
    {
        bitset<numberSize> ans = 0;
        bool carry = 0;
        for (int i = 0; i < numberSize; i++)
        {
            ans[i] = a[i]^b[i]^carry;
            carry = (a[i]&b[i])|(carry&(a[i]|b[i]));
        }
        return ans;
    }
    void operator+=(bitset<numberSize> &a, bitset<numberSize> b)
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
    void operator-=(bitset<numberSize> &a, bitset<numberSize> b)
    {
        a = a - b;
    }




    bitset<numberSize> operator*(bitset<numberSize> a, bitset<numberSize> b)
    {
        bitset<numberSize> ans = 0;
        if (a.count() > b.count()) swap(a, b);
        for (int i = 0; i < numberSize; i++) if (a[i]) ans += (b<<i);
        return ans;
    }
    void operator*=(bitset<numberSize> &a, bitset<numberSize> b)
    {
        a = a*b;
    }




    bitset<numberSize> operator/(bitset<numberSize> a, bitset<numberSize> b)
    {
        return helper::div(a, b).first;
    }
    void operator/=(bitset<numberSize> &a, bitset<numberSize> b)
    {
        a = a / b;
    }
    bitset<numberSize> operator%(bitset<numberSize> a, bitset<numberSize> b)
    {
        return helper::div(a, b).second;
    }
    void operator%=(bitset<numberSize> &a, bitset<numberSize> b)
    {
        a = a % b;
    }




    bool operator<(bitset<numberSize> a, bitset<numberSize> b)
    {
        if (a[numberSize-1]^b[numberSize-1]) return a[numberSize-1];
        for (int i = numberSize-2; i >= 0; i--) if (a[i]^b[i]) return b[i];
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
    bitset<numberSize> n, pub, priv;

    rsa(bitset<numberSize> N, bitset<numberSize> E, bitset<numberSize> D): n(N), pub(E), priv(D)
    {}

    bitset<numberSize> encrypt(bitset<numberSize> msg)
    {
        return pwr(msg, pub);
    }

    bitset<numberSize> decrypt(bitset<numberSize> msg)
    {
        return pwr(msg, priv);
    }



    vector<bitset<numberSize>> encrypt(string msg)
    {
        vector<bitset<numberSize>> encrypted;
        if (msg.size()%chunkSize != 0) msg += string(chunkSize - (msg.size()%chunkSize), 0);
        for (int i = 0; i < msg.size(); i += chunkSize)
        {
            int ind = 0;
            bitset<numberSize> chunk;
            for (int j = 0; j < chunkSize; j++) for (int k = 0; k < 7; k++)  chunk[ind++] = msg[i+j]&(1<<k);
            encrypted.push_back(encrypt(chunk));
        }
        return encrypted;
    }

    string decrypt(vector<bitset<numberSize>> msg)
    {
        string decrypted = "";
        for (int i = 0; i < msg.size(); i++)
        {
            int ind = 0;
            string temp = string(chunkSize, 0);
            bitset<numberSize> dec = decrypt(msg[i]);
            for (int j = 0; j < chunkSize; j++) for (int k = 0; k < 7; k++) if (dec[ind++]) temp[j] ^= (1<<k);
            decrypted += temp;
        }
        while (!decrypted.empty() && decrypted.back() == 0) decrypted.pop_back();
        return decrypted;
    }



private:
    bitset<numberSize> pwr(bitset<numberSize> &a, bitset<numberSize> &b)
    {
        if (b.count()==0) return a;
        bool tmp = b[0];
        b >>= 1;
        bitset<numberSize> temp = pwr(a, b);
        temp = (temp*temp)%n;
        if (tmp) temp = (temp*a)%n;
        return temp;
    }
};


int main()
{
    rsa ins(bitset<numberSize>(67072), bitset<numberSize>(3), bitset<numberSize>(44715));
    string s = "hello";
    auto v = ins.encrypt(s);
    s = ins.decrypt(v);
    cout << s << '\n';
    return 0;
}