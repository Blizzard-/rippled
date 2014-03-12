//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012, 2013 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include "../../../beast/beast/unit_test/suite.h"

namespace ripple {

namespace detail {
    // A simple wrapper for a BIGNUM to make it
    // easier to allocate, construct, and free them
    struct BigNum
    {
        BIGNUM* num;

        BigNum& operator=(BigNum const&) = delete;

        BigNum ()
            : num (BN_new ())
        {

        }

        BigNum (const char *hex)
            : num (BN_new ())
        {
            BN_hex2bn (&num, hex);
        }

        BigNum (unsigned char const* ptr, size_t len)
            : num (BN_new ())
        {
            set (ptr, len);
        }

        BigNum (BigNum const& other)
            : num (BN_new ())
        {
            if (BN_copy (num, other.num) == nullptr)
                BN_clear (num);
        }

        ~BigNum ()
        {
            BN_free (num);
        }

        operator BIGNUM* ()
        {
            return num;
        }
        
        operator BIGNUM const* () const
        {
            return num;
        }

        bool set (unsigned char const* ptr, size_t len)
        {
            if (BN_bin2bn (ptr, len, num) == nullptr)
                return false;

            return true;
        }
    };

    class SignaturePart
    {
    private:
        size_t m_skip;
        BigNum m_bn;

    public:
        SignaturePart (unsigned char const* sig, size_t len)
            : m_skip (0)
        {
            // The format is: <02> <len> <sig>
            if ((sig[0] != 0x02) || (len < 3))
                return;
            
            size_t sigLen = sig[1];
            
            // Can't be longer than the data we have and must
            // be between 1 and 33 bytes.
            if ((sigLen > len) || (sigLen < 2) || (sigLen > 33))
                return;

            // The signature can't be negative
            if ((sig[2] & 0x80) != 0)
                return;

            // It can't be zero
            if ((sig[2] == 0) && (len == 1))
                return;

            // And it can't be padded
            if ((sig[2] == 0) && ((sig[3] & 0x80) == 0))
                return;

            // Load the signature but skip the marker prefix and length
            if (m_bn.set (sig + 2, sigLen))
                m_skip = sigLen + 2;
        }

        bool valid () const
        {
            return m_skip != 0;
        }

        // The signature as a BIGNUM
        BigNum getBigNum () const
        {
            return m_bn;
        }
        
        // Returns the number of bytes to skip for this signature part
        size_t skip () const
        {
            return m_skip;
        }
    };

    // The SECp256k1 modulus
    static BigNum const modulus (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
}

bool isCanonicalECDSASig (void const* vSig, size_t sigLen, ECDSA strict_param)
{
    // Make sure signature is canonical
    // To protect against signature morphing attacks
    // See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
    // and https://github.com/sipa/bitcoin/commit/58bc86e37fda1aec270bccb3df6c20fbd2a6591c

    // Signature should be:
    // <30> <len> [ <02> <lenR> <R> ] [ <02> <lenS> <S> ]

    unsigned char const* sig = reinterpret_cast<unsigned char const*> (vSig);

    if ((sigLen < 10) || (sigLen > 72))
        return false;

    if ((sig[0] != 0x30) || (sig[1] != (sigLen - 2)))
        return false;
    
    // The first two bytes are verified. Eat them.
    sig += 2;
    sigLen -= 2;

    // Verify the R signature
    detail::SignaturePart sigR (sig, sigLen);
    
    if (!sigR.valid ())
        return false;

    // Eat the number of bytes we consumed
    sig += sigR.skip ();
    sigLen -= sigR.skip ();
    
    // Verify the S signature
    detail::SignaturePart sigS (sig, sigLen);
    
    if (!sigS.valid ())
        return false;
    
    // Eat the number of bytes we consumed
    sig += sigS.skip ();
    sigLen -= sigS.skip ();

    // Nothing should remain at this point.
    if (sigLen != 0)
        return false;

    // Check whether R or S are greater than the modulus.
    auto bnR (sigR.getBigNum ());
    auto bnS (sigS.getBigNum ());

    if (BN_cmp (bnR, detail::modulus) != -1)
        return false;

    if (BN_cmp (bnS, detail::modulus) != -1)
        return false; 

    // For a given signature, (R,S), the signature (R, N-S) is also valid. For
    // a signature to be fully-canonical, the smaller of these two values must
    // be specified. If operating in strict mode, check that as well.
    if (strict_param == ECDSA::strict)
    {
        detail::BigNum mS;

        if (BN_sub (mS, detail::modulus, bnS) == 0)
            return false;

        if (BN_cmp (bnS, mS) == 1)
            return false;
    }

    return true;
}

// Returns true if original signature was alread canonical
bool makeCanonicalECDSASig (void* vSig, size_t& sigLen)
{
// Signature is (r,s) where 0 < s < g
// If (g-s)<g, replace signature with (r,g-s)

    unsigned char * sig = reinterpret_cast<unsigned char *> (vSig);
    bool ret = false;

    // Find internals
    int rLen = sig[3];
    int sPos = rLen + 6, sLen = sig[rLen + 5];

    detail::BigNum origS, newS;
    BN_bin2bn (&sig[sPos], sLen, origS);
    BN_sub (newS, detail::modulus, origS);

    if (BN_cmp (origS, newS) == 1)
    { // original signature is not fully canonical
        unsigned char newSbuf [64];
        int newSlen = BN_bn2bin (newS, newSbuf);

        if ((newSbuf[0] & 0x80) == 0)
        { // no extra padding byte is needed
            sig[1] = sig[1] - sLen + newSlen;
            sig[sPos - 1] = newSlen;
            memcpy (&sig[sPos], newSbuf, newSlen);
        }
        else
        { // an extra padding byte is needed
            sig[1] = sig[1] - sLen + newSlen + 1;
            sig[sPos - 1] = newSlen + 1;
            sig[sPos] = 0;
            memcpy (&sig[sPos + 1], newSbuf, newSlen);
        }
        sigLen = sig[1] + 2;
    }
    else
        ret = true;

    return ret;
}

template <class FwdIter, class Container>
void hex_to_binary (FwdIter first, FwdIter last, Container& out)
{
    struct Table
    {
        int val[256];
        Table ()
        {
            std::fill (val, val+256, 0);
            for (int i = 0; i < 10; ++i)
                val ['0'+i] = i;
            for (int i = 0; i < 6; ++i)
            {
                val ['A'+i] = 10 + i;
                val ['a'+i] = 10 + i;
            }
        }
        int operator[] (int i)
        {
           return val[i];
        }
    };

    static Table lut;
    out.reserve (std::distance (first, last) / 2);
    while (first != last)
    {
        auto const hi (lut[(*first++)]);
        auto const lo (lut[(*first++)]);
        out.push_back ((hi*16)+lo);
    }
}

class ECDSACanonical_test : public beast::unit_test::suite
{
public:
    bool isCanonical (std::string const& hex)
    {
        Blob j;
        hex_to_binary (hex.begin(), hex.end(), j);
        return isCanonicalECDSASig (&j[0], j.size(), ECDSA::not_strict);
    }

    void run ()
    {
        expect (isCanonical("304402203932c892e2e550f3af8ee4ce9c215a87f9bb"
            "831dcac87b2838e2c2eaa891df0c022030b61dd36543125d56b9f9f3a1f"
            "53189e5af33cdda8d77a5209aec03978fa001"), "canonical signature");

        expect (isCanonical("30450220076045be6f9eca28ff1ec606b833d0b87e70b"
            "2a630f5e3a496b110967a40f90a0221008fffd599910eefe00bc803c688"
            "eca1d2ba7f6b180620eaa03488e6585db6ba01"), "canonical signature");

        expect (isCanonical("3046022100876045be6f9eca28ff1ec606b833d0b87e7"
            "0b2a630f5e3a496b110967a40f90a0221008fffd599910eefe00bc803c688c"
            "2eca1d2ba7f6b180620eaa03488e6585db6ba"), "canonical signature");

        expect (!isCanonical("3005" "0201FF" "0200"), "tooshort");

        expect (!isCanonical("3047"
            "0221005990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "022200002d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "toolong");

        expect (!isCanonical("3144"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "type");

        expect (!isCanonical("3045"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "totallength");

        expect (!isCanonical(
            "301F" "01205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1"),
            "Slenoob");

        expect (!isCanonical("3045"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed00"),
            "R+S");

        expect (!isCanonical("3044"
            "01205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "Rtype");

        expect (!isCanonical("3024" "0200"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "Rlen=0");

        expect (!isCanonical("3044"
            "02208990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "R<0");

        expect (!isCanonical("3045"
            "0221005990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "Rpadded");

        expect (!isCanonical("3044"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105012"
            "02d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "Stype");

        expect (!isCanonical("3024"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "0200"),
            "Slen=0");

        expect (!isCanonical("3044"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "0220fd5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "S<0");

        expect (!isCanonical("3045"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba6105"
            "0221002d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695ed"),
            "Spadded");

    }
};

BEAST_DEFINE_TESTSUITE(ECDSACanonical,sslutil,ripple);

}
