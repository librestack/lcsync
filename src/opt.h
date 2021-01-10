/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _OPT_H
#define _OPT_H

enum opt_type {
	OTYPE_BOOL,
	OTYPE_INT,
	OTYPE_STR
};

typedef struct opt_s opt_t;
struct opt_s {
	void	*var;
	char	oshort;
	char	olong[32];
	char	help[128];
	enum opt_type type;
	int (*f)(opt_t *opt, int *argc, char **argv[]);
};

typedef struct opt_parser_s {
	int	optc;
	opt_t	optv[];
} opt_parser_t;

/* initialise option parser with opts options */
opt_parser_t *opt_init(int opts);

/* free parser */
void opt_free(opt_parser_t *parser);

/* register new option with parser */
int opt_new(opt_parser_t *parser, opt_t *opt);

/* parse option arguments */
int opt_parse(opt_parser_t *parser, int *argc, char **argv[]);

/* set boolean (int) to true (1) */
int opt_set_true(opt_t *opt);

/* set integer value */
int opt_set_int(opt_t *opt, int *argc, char **argv[]);

/* set string value */
int opt_set_str(opt_t *opt, int *argc, char **argv[]);

#endif /* _OPT_H */
