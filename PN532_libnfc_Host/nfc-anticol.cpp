/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */

/**
 * @file nfc-anticol.c
 * @brief Generates one ISO14443-A anti-collision process "by-hand"
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <nfc/nfc.h>
#include <string>
#include <json/json.h>
#include "../../resource/tool.h"


#define SAK_FLAG_ATS_SUPPORTED 0x20

#define MAX_FRAME_LEN 264

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;
static size_t szRx = sizeof(abtRx);
static uint8_t abtRawUid[12];
static uint8_t abtAtqa[2];
static uint8_t abtSak;
static uint8_t abtAts[MAX_FRAME_LEN];
static uint8_t szAts = 0;
static size_t szCL = 1;//Always start with Cascade Level 1 (CL1)
static nfc_device *pnd;

static bool    quiet_output = false;
static bool    force_rats = false;
static bool    timed = false;
static bool    iso_ats_supported = false;

// ISO14443A Anti-Collision Commands
static uint8_t  abtReqa[1] = { 0x26 };
static uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
static uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t  abtRats[4] = { 0xe0, 0x50, 0x00, 0x00 };
static uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };
#define CASCADE_BIT 0x04

static  bool
transmit_bits(const uint8_t *pbtTx, const size_t szTxBits)
{
  uint32_t cycles = 0;
  // Transmit the bit frame command, we don't use the arbitrary parity feature
  if (timed) {
    if ((szRxBits = nfc_initiator_transceive_bits_timed(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL, &cycles)) < 0)
      return false;
    if ((!quiet_output) && (szRxBits > 0)) {
      printf("Response after %u cycles\n", cycles);
    }
  } else {
    if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
      return false;
  }
  // Succesful transfer
  return true;
}


static  bool
transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
  uint32_t cycles = 0;
  int res;
  // Transmit the command bytes
  if (timed) {
    if ((res = nfc_initiator_transceive_bytes_timed(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), &cycles)) < 0)
      return false;
    if ((!quiet_output) && (res > 0)) {
      printf("Response after %u cycles\n", cycles);
    }
  } else {
    if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
      return false;
  }
  szRx = res;
  // Succesful transfer
  return true;
}

DWORD Echo(PVOID buffer, DWORD count);
DWORD Echo(std::wstring str);
#define ERR(x) (fprintf(stderr, "%s\n", (x)))

int
nfc_query_card_info()
{
  //int     arg;
  
  nfc_context *context;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

  // Try to open the NFC reader
  pnd = nfc_open(context, NULL);

  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Initialise NFC device as "initiator"
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Configure the CRC
  if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Disable 14443-4 autoswitching
  if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n\n", nfc_device_get_name(pnd));

  // Send the 7 bits request command specified in ISO 14443A (0x26)
  if (!transmit_bits(abtReqa, 7)) {
    printf("Error: No tag available\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  memcpy(abtAtqa, abtRx, 2);

  // Anti-collision
  transmit_bytes(abtSelectAll, 2);

  // Check answer
  if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
    printf("WARNING: BCC check failed!\n");
  }

  // Save the UID CL1
  memcpy(abtRawUid, abtRx, 12);

  //Prepare and send CL1 Select-Command
  memcpy(abtSelectTag + 2, abtRx, 5);
  iso14443a_crc_append(abtSelectTag, 7);
  transmit_bytes(abtSelectTag, 9);
  abtSak = abtRx[0];

  // Test if we are dealing with a CL2
  if (abtSak & CASCADE_BIT) {
    szCL = 2;//or more
    // Check answer
    if (abtRawUid[0] != 0x88) {
      printf("WARNING: Cascade bit set but CT != 0x88!\n");
    }
  }

  if (szCL == 2) {
    // We have to do the anti-collision for cascade level 2

    // Prepare CL2 commands
    abtSelectAll[0] = 0x95;

    // Anti-collision
    transmit_bytes(abtSelectAll, 2);

    // Check answer
    if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
      printf("WARNING: BCC check failed!\n");
    }

    // Save UID CL2
    memcpy(abtRawUid + 4, abtRx, 4);

    // Selection
    abtSelectTag[0] = 0x95;
    memcpy(abtSelectTag + 2, abtRx, 5);
    iso14443a_crc_append(abtSelectTag, 7);
    transmit_bytes(abtSelectTag, 9);
    abtSak = abtRx[0];

    // Test if we are dealing with a CL3
    if (abtSak & CASCADE_BIT) {
      szCL = 3;
      // Check answer
      if (abtRawUid[0] != 0x88) {
        printf("WARNING: Cascade bit set but CT != 0x88!\n");
      }
    }

    if (szCL == 3) {
      // We have to do the anti-collision for cascade level 3

      // Prepare and send CL3 AC-Command
      abtSelectAll[0] = 0x97;
      transmit_bytes(abtSelectAll, 2);

      // Check answer
      if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
        printf("WARNING: BCC check failed!\n");
      }

      // Save UID CL3
      memcpy(abtRawUid + 8, abtRx, 4);

      // Prepare and send final Select-Command
      abtSelectTag[0] = 0x97;
      memcpy(abtSelectTag + 2, abtRx, 5);
      iso14443a_crc_append(abtSelectTag, 7);
      transmit_bytes(abtSelectTag, 9);
      abtSak = abtRx[0];
    }
  }

  // Request ATS, this only applies to tags that support ISO 14443A-4
  if (abtRx[0] & SAK_FLAG_ATS_SUPPORTED) {
    iso_ats_supported = true;
  }
  if ((abtRx[0] & SAK_FLAG_ATS_SUPPORTED) || force_rats) {
    iso14443a_crc_append(abtRats, 2);
    if (transmit_bytes(abtRats, 4)) {
      memcpy(abtAts, abtRx, szRx);
      szAts = (uint8_t)szRx;
    }
  }

  // Done, halt the tag now
  iso14443a_crc_append(abtHalt, 2);
  transmit_bytes(abtHalt, 4);

  using namespace std;
  string uid, atqa, sak;
  char sbuf[32]{};

  printf("\nFound tag with\n UID: ");
  switch (szCL) {
    case 1:
      sprintf_s(sbuf, "%02x%02x%02x%02x", abtRawUid[0], abtRawUid[1], abtRawUid[2], abtRawUid[3]);
      break;
    case 2:
      sprintf_s(sbuf, "%02x%02x%02x%02x%02x%02x%02x",
          abtRawUid[1], abtRawUid[2], abtRawUid[3],
          abtRawUid[4], abtRawUid[5], abtRawUid[6], abtRawUid[7]
      );
      break;
    case 3:
      sprintf_s(sbuf, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
          abtRawUid[1], abtRawUid[2], abtRawUid[3],
          abtRawUid[5], abtRawUid[6], abtRawUid[7],
          abtRawUid[8], abtRawUid[9], abtRawUid[10], abtRawUid[11]
      );
      break;
  }
  uid = sbuf;
  printf("\n");
  printf("ATQA: %02x%02x\n SAK: %02x\n", abtAtqa[1], abtAtqa[0], abtSak);
  sprintf_s(sbuf, "%02x%02x", abtAtqa[1], abtAtqa[0]);
  atqa = sbuf;
  sprintf_s(sbuf, "%02x", abtSak);
  sak = sbuf;
  Json::Value myvalue;
  myvalue["uid"] = uid;
  myvalue["atqa"] = atqa;
  myvalue["sak"] = sak;
  Json::FastWriter fastWriter;
  Echo(s2ws(fastWriter.write(myvalue)));

  if (szAts > 1) { // if = 1, it's not actual ATS but error code
    if (force_rats && ! iso_ats_supported) {
      printf(" RATS forced\n");
    }
    printf(" ATS: ");
  }

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
