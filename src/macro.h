/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#define aitoin6(ai) &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr)
