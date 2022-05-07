/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net> */

#define aitoin6(ai) &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr)
