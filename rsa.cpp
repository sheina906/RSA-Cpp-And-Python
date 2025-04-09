#include <bitset>
#define sz 1024
using namespace std;

namespace bitsetOperations
{
    bitset<sz> operator+(bitset<sz> a, bitset<sz> b);
    void operator+=(bitset<sz> &a, bitset<sz> b);
    bitset<sz> operator-(bitset<sz> num);
    bitset<sz> operator-(bitset<sz> a, bitset<sz> b);
    void operator-=(bitset<sz> &a, bitset<sz> b);

    bitset<sz> operator*(bitset<sz> a, bitset<sz> b);
    void operator*=(bitset<sz> &a, bitset<sz> b);

    bitset<sz> operator/(bitset<sz> a, bitset<sz> b);
    void operator/=(bitset<sz> &a, bitset<sz> b);
    bitset<sz> operator%(bitset<sz> a, bitset<sz> b);
    void operator%=(bitset<sz> &a, bitset<sz> b);

    void operator%=(bitset<sz> &a, bitset<sz> b);
    bool operator<(bitset<sz> a, bitset<sz> b);
    bool operator>(bitset<sz> a, bitset<sz> b);
    bool operator<=(bitset<sz> a, bitset<sz> b);
    bool operator>=(bitset<sz> a, bitset<sz> b);



    namespace helper
    {
        pair<bitset<sz>, bitset<sz>> div(bitset<sz> a, bitset<sz> b)
        {
            bitset<sz> remainder = 0, qoutient = 0;

            for (int i = sz-1; i >= 0; i--)
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



    bitset<sz> operator+(bitset<sz> a, bitset<sz> b)
    {
        bitset<sz> ans = 0;
        bool carry = 0;
        for (int i = 0; i < sz; i++)
        {
            ans[i] = a[i]^b[i]^carry;
            carry = (a[i]&b[i])|(carry&(a[i]|b[i]));
        }
        return ans;
    }
    void operator+=(bitset<sz> &a, bitset<sz> b)
    {
        a = a + b;
    }
    bitset<sz> operator-(bitset<sz> num)
    {
        num = ~num;
        return num + bitset<sz>(1);
    }
    bitset<sz> operator-(bitset<sz> a, bitset<sz> b)
    {
        return a + (-b);
    }
    void operator-=(bitset<sz> &a, bitset<sz> b)
    {
        a = a - b;
    }




    bitset<sz> operator*(bitset<sz> a, bitset<sz> b)
    {
        bitset<sz> ans = 0;
        if (a.count() > b.count()) swap(a, b);
        for (int i = 0; i < sz; i++) if (a[i]) ans += (b<<i);
        return ans;
    }
    void operator*=(bitset<sz> &a, bitset<sz> b)
    {
        a = a*b;
    }




    bitset<sz> operator/(bitset<sz> a, bitset<sz> b)
    {
        return helper::div(a, b).first;
    }
    void operator/=(bitset<sz> &a, bitset<sz> b)
    {
        a = a / b;
    }
    bitset<sz> operator%(bitset<sz> a, bitset<sz> b)
    {
        return helper::div(a, b).second;
    }
    void operator%=(bitset<sz> &a, bitset<sz> b)
    {
        a = a % b;
    }




    bool operator<(bitset<sz> a, bitset<sz> b)
    {
        if (a[sz-1]^b[sz-1]) return a[sz-1];
        for (int i = sz-2; i >= 0; i--) if (a[i]^b[i]) return b[i];
        return false;
    }

    bool operator>(bitset<sz> a, bitset<sz> b)
    {
        return !(a < b) && !(a == b);
    }

    bool operator<=(bitset<sz> a, bitset<sz> b)
    {
        return a < b || a == b;
    }

    bool operator>=(bitset<sz> a, bitset<sz> b)
    {
        return !(a < b);
    }
}
using namespace bitsetOperations;





struct rsa
{
    bitset<sz> n, pub, priv;

    rsa(bitset<sz> N, bitset<sz> E, bitset<sz> D): n(N), pub(E), priv(D)
    {}

    bitset<sz> encrypt(bitset<sz> msg)
    {
        return pwr(msg, pub);
    }

    bitset<sz> decrypt(bitset<sz> enc)
    {
        return pwr(enc, priv);
    }


private:
    bitset<sz> pwr(bitset<sz> &a, bitset<sz> &b)
    {
        if (b.count()==0) return a;
        bool tmp = b[0];
        b >>= 1;
        bitset<sz> temp = pwr(a, b);
        temp = (temp*temp)%n;
        if (tmp) temp = (temp*a)%n;
        return temp;
    }
};