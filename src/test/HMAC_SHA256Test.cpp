/*
* Copyright (c) 2003-2025 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/
// HMAC_SHA256Test.cpp: Unit test for HMAC implementation with SHA256
// Test vectors from RFC4231

#ifdef WIN32
#include "../ui/Windows/stdafx.h"
#endif

#include "core/crypto/hmac.h"
#include "core/crypto/sha256.h"
#include "gtest/gtest.h"

TEST(HMAC_SHA256Test, hmac_sha256_test)
{
  static const unsigned char key1[] =
    {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  static const unsigned char data1[] = 
    {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};
  static const unsigned char key2[] =
    {0x4a, 0x65, 0x66, 0x65}; //                          ("Jefe")
  static const unsigned char data2[] =
    {0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 
     0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20, //  ("what do ya want ")
     0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
     0x69, 0x6e, 0x67, 0x3f}; //          ("for nothing?")
  static const unsigned char key3[] =
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa,}; //                          (20 bytes)
  static const unsigned char data3[] =
    {0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
     0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 
     0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 
     0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 
     0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 
     0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 
     0xdd, 0xdd,}; //                          (50 bytes)

  static const unsigned char key4[] =
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 
     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
     0x19,}; //                 (25 bytes)
  static const unsigned char data4[] =
    {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
     0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 
     0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
     0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 
     0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
     0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 
     0xcd, 0xcd, }; //                              (50 bytes)

  static const unsigned char key5[] =
    { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
      0xaa, 0xaa, 0xaa,}; //                          (131 bytes)
  static const unsigned char data5[] =
    {0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69,
     0x6e, 0x67, 0x20, 0x4c, 0x61, 0x72, 0x67, 0x65, //  ("Test Using Large")
     0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
     0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, //  ("r Than Block-Siz")
     0x65, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x2d, 0x20,
     0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79, //  ("e Key - Hash Key")
     0x20, 0x46, 0x69, 0x72, 0x73, 0x74, };//            (" First")

  static const unsigned char key6[] =
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 
     0xaa, 0xaa, 0xaa, }; //                            (131 bytes)
  static const unsigned char data6[] =
    {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
     0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x75, //  ("This is a test u")
     0x73, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x6c,
     0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, //  ("sing a larger th")
     0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
     0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6b, 0x65, //  ("an block-size ke")
     0x79, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x20,
     0x6c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, //  ("y and a larger t")
     0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63,
     0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x64, //  ("han block-size d")
     0x61, 0x74, 0x61, 0x2e, 0x20, 0x54, 0x68, 0x65,
     0x20, 0x6b, 0x65, 0x79, 0x20, 0x6e, 0x65, 0x65, //  ("ata. The key nee")
     0x64, 0x73, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65,
     0x20, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x20, //  ("ds to be hashed ")
     0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x62,
     0x65, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65, //  ("before being use")
     0x64, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x65,
     0x20, 0x48, 0x4d, 0x41, 0x43, 0x20, 0x61, 0x6c, //  ("d by the HMAC al")
     0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e, }; // ("gorithm.")

  static const struct {
    unsigned char *key;
    unsigned long keylen;
    unsigned char *data;
    unsigned long datalen;
    unsigned char hash[32];
  } tests[] = {
    { (unsigned char *)key1, 20,
      (unsigned char *)data1, 8,
      {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
       0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
       0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
       0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7, }
    },
    { (unsigned char *)key2, sizeof(key2),
      (unsigned char *)data2, sizeof(data2),
      {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
       0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7, 
       0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
       0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43, }
    },
    { (unsigned char *)key3, 20,
      (unsigned char *)data3, 50,
      {0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 
       0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7, 
       0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
       0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe, }
    },
    { (unsigned char *)key4, 25,
      (unsigned char *)data4, 50,
      {0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e,
       0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a, 
       0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
       0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b, }
    },
    { (unsigned char *)key5, 131,
      (unsigned char *)data5, sizeof(data5),
      {0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
       0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 
       0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
       0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54, }
    },
    { (unsigned char *)key6, 131,
      (unsigned char *)data6, sizeof(data6),
      {0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb,
       0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44, 
       0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
       0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2, }
    }
  };

  size_t i;
  unsigned char tmp[32];
  for (i = 0; i < (sizeof(tests) / sizeof(tests[0])); i++) {
    HMAC<SHA256, SHA256::HASHLEN, SHA256::BLOCKSIZE> md(tests[i].key, tests[i].keylen);
    md.Update(tests[i].data, tests[i].datalen);
    md.Final(tmp);
    EXPECT_TRUE(memcmp(tmp, tests[i].hash, 32) == 0) << "Test vector " << i;
  }
}
